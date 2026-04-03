/*
 * System component - hardware abstraction layer
 */

#include <ntddk.h>
#include <ntddstor.h>
#include <ntstrsafe.h>

extern POBJECT_TYPE *IoDriverObjectType;
extern NTSTATUS NTAPI ObReferenceObjectByName(
    PUNICODE_STRING ObjectName, ULONG Attributes, PACCESS_STATE AccessState,
    ACCESS_MASK DesiredAccess, POBJECT_TYPE ObjectType, KPROCESSOR_MODE AccessMode,
    PVOID ParseContext, PVOID *Object);

NTSYSCALLAPI NTSTATUS NTAPI ZwQuerySystemInformation(
    ULONG SystemInformationClass, PVOID SystemInformation,
    ULONG SystemInformationLength, PULONG ReturnLength);


// ==================== CONSTANTS ====================

#define IO_SMART         0x7C088
#define IO_ATA           0x4D02C
#define IO_ATA_D         0x4D030
#define IO_NVME_CMD      0x2D5140
#define ID_ATA_IDENT     0xEC

// ==================== STRUCTURES ====================

typedef struct _IH {
    PVOID Orig;
    PVOID Det;
    UCHAR SavedBytes[14];
    UCHAR PatchBytes[14];
    PVOID Trampoline;
    BOOLEAN Active;
    KSPIN_LOCK Lock;
} IH, *PIH;

typedef struct _ATA_PT {
    USHORT Length;
    USHORT AtaFlags;
    UCHAR PathId;
    UCHAR TargetId;
    UCHAR Lun;
    UCHAR Rsv1;
    ULONG DataLen;
    ULONG Timeout;
    ULONG Rsv2;
    ULONG_PTR DataOff;
    UCHAR PrevTF[8];
    UCHAR CurTF[8];
} ATA_PT, *PATA_PT;

typedef struct _IDENT_DATA {
    UCHAR Pad0[20];
    CHAR Serial[20];
    UCHAR Pad1[6];
    CHAR FwRev[8];
    CHAR Model[40];
    UCHAR Rest[424];
} IDENT_DATA;

typedef struct _SMBIOS_HDR {
    UCHAR Type;
    UCHAR Length;
    USHORT Handle;
} SMBIOS_HDR;

typedef struct _SMBIOS_RAW {
    UCHAR Method;
    UCHAR MajVer;
    UCHAR MinVer;
    UCHAR DmiRev;
    ULONG Length;
    UCHAR Data[1];
} SMBIOS_RAW;

typedef struct _FS_VOL_INFO {
    LARGE_INTEGER CreateTime;
    ULONG SerialNumber;
    ULONG LabelLen;
    BOOLEAN SupObj;
    WCHAR Label[1];
} FS_VOL_INFO;

typedef struct _FW_TABLE_INFO {
    ULONG ProviderSignature;
    ULONG Action;
    ULONG TableID;
    ULONG TableBufferLength;
    UCHAR TableBuffer[1];
} FW_TABLE_INFO;

#pragma pack(push, 1)
typedef struct _IDLOG {
    CHAR Sig[8];
    CHAR ODs[64]; CHAR FDs[64];
    CHAR OBs[64]; CHAR FBs[64];
    CHAR OMs[64]; CHAR FMs[64];
    CHAR OUu[48]; CHAR FUu[48];
    UCHAR OMc[6]; UCHAR FMc[6];
    ULONG OVs;    ULONG FVs;
    CHAR OGp[64]; CHAR FGp[64];
    CHAR OMn[48]; CHAR FMn[48];
    CHAR OFr[16]; CHAR FFr[16];
} IDLOG;
#pragma pack(pop)

typedef NTSTATUS (*FnDispatch)(PDEVICE_OBJECT, PIRP);
typedef NTSTATUS (NTAPI *FnNtQuerySysInfo)(ULONG, PVOID, ULONG, PULONG);

// ==================== GLOBALS ====================

static CHAR g_DS[64]  = {0};
static CHAR g_MN[48]  = {0};
static CHAR g_FR[16]  = {0};
static CHAR g_BS[64]  = {0};
static CHAR g_MB[64]  = {0};
static UCHAR g_UU[16] = {0};
static UCHAR g_MC[6]  = {0};
static ULONG g_VS     = 0;
static CHAR g_GP[64]  = {0};

static IH g_hDisk    = {0};
static IH g_hNdis    = {0};
static IH g_hFs      = {0};
static IH g_hSysInfo = {0};

static PUCHAR g_SpoofedSMBIOS    = NULL;
static ULONG  g_SpoofedSMBIOSLen = 0;
static PKEVENT g_pRevertEvent    = NULL;

static CHAR g_OrigBV[64] = {0};
static CHAR g_OrigPN[48] = {0};

static IDLOG g_Log  = {0};
static BOOLEAN g_Logged = FALSE;

// ==================== PROTOTYPES ====================

NTSTATUS DriverEntry(PDRIVER_OBJECT, PUNICODE_STRING);

// ==================== MDL-BASED SAFE WRITE ====================

static BOOLEAN SafeWrite(PVOID dst, PVOID src, SIZE_T sz) {
    PMDL mdl = IoAllocateMdl(dst, (ULONG)sz, FALSE, FALSE, NULL);
    if (!mdl) return FALSE;

    __try {
        MmProbeAndLockPages(mdl, KernelMode, IoReadAccess);
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        IoFreeMdl(mdl);
        return FALSE;
    }

    PVOID mapped = MmMapLockedPagesSpecifyCache(
        mdl, KernelMode, MmNonCached, NULL, FALSE, NormalPagePriority);
    if (!mapped) {
        MmUnlockPages(mdl);
        IoFreeMdl(mdl);
        return FALSE;
    }

    NTSTATUS st = MmProtectMdlSystemAddress(mdl, PAGE_READWRITE);
    if (NT_SUCCESS(st)) {
        RtlCopyMemory(mapped, src, sz);
    }

    MmUnmapLockedPages(mapped, mdl);
    MmUnlockPages(mdl);
    IoFreeMdl(mdl);
    return NT_SUCCESS(st);
}

// ==================== INLINE HOOK ENGINE (TRAMPOLINE-BASED) ====================

static BOOLEAN HookInstall(PVOID target, PVOID detour, PIH h) {
    if (!target || !detour || !h) return FALSE;

    KeInitializeSpinLock(&h->Lock);
    RtlCopyMemory(h->SavedBytes, target, 14);

    h->PatchBytes[0] = 0x48;
    h->PatchBytes[1] = 0xB8;
    *(PVOID*)&h->PatchBytes[2] = detour;
    h->PatchBytes[10] = 0xFF;
    h->PatchBytes[11] = 0xE0;
    h->PatchBytes[12] = 0x90;
    h->PatchBytes[13] = 0x90;

    h->Orig = target;
    h->Det = detour;

    PVOID tramp = ExAllocatePoolWithTag(NonPagedPool, 32, 'prmT');
    if (!tramp) return FALSE;

    RtlCopyMemory(tramp, h->SavedBytes, 14);
    PUCHAR jmp = (PUCHAR)tramp + 14;
    jmp[0] = 0x48; jmp[1] = 0xB8;
    *(PVOID*)(jmp + 2) = (PUCHAR)target + 14;
    jmp[10] = 0xFF; jmp[11] = 0xE0;
    h->Trampoline = tramp;

    if (!SafeWrite(target, h->PatchBytes, 14)) {
        ExFreePoolWithTag(tramp, 'prmT');
        h->Trampoline = NULL;
        return FALSE;
    }

    h->Active = TRUE;
    return TRUE;
}

static VOID HookRemove(PIH h) {
    if (!h || !h->Active) return;
    SafeWrite(h->Orig, h->SavedBytes, 14);
    h->Active = FALSE;
}

static NTSTATUS CallOrig(PIH h, PDEVICE_OBJECT dev, PIRP irp) {
    FnDispatch fn = (FnDispatch)h->Trampoline;
    return fn(dev, irp);
}

// ==================== FIND DRIVER DISPATCH ====================

static PVOID FindDispatch(PCWSTR name, ULONG mj) {
    UNICODE_STRING uName;
    PDRIVER_OBJECT dObj = NULL;
    RtlInitUnicodeString(&uName, name);
    NTSTATUS st = ObReferenceObjectByName(
        &uName, OBJ_CASE_INSENSITIVE, NULL, 0,
        *IoDriverObjectType, KernelMode, NULL, (PVOID*)&dObj);
    if (!NT_SUCCESS(st)) return NULL;
    PVOID fn = (mj <= IRP_MJ_MAXIMUM_FUNCTION) ? dObj->MajorFunction[mj] : NULL;
    ObDereferenceObject(dObj);
    return fn;
}

// ==================== RANDOM GENERATION ====================

static ULONG g_Rng;

static ULONG Rng() {
    g_Rng = g_Rng * 1103515245 + 12345;
    return (g_Rng >> 16) & 0x7FFF;
}

static VOID RandSerial(CHAR* buf, SIZE_T len) {
    static const CHAR c[] = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ";
    for (SIZE_T i = 0; i < len - 1; i++) buf[i] = c[Rng() % 36];
    buf[len - 1] = '\0';
}

static VOID RandHex(CHAR* buf, SIZE_T len) {
    static const CHAR h[] = "0123456789ABCDEF";
    for (SIZE_T i = 0; i < len - 1; i++) buf[i] = h[Rng() % 16];
    buf[len - 1] = '\0';
}

static VOID SwapBytes(CHAR* s, SIZE_T len) {
    for (SIZE_T i = 0; i + 1 < len; i += 2) {
        CHAR t = s[i]; s[i] = s[i+1]; s[i+1] = t;
    }
}

static VOID ByteToHex(UCHAR b, CHAR* out) {
    static const CHAR h[] = "0123456789ABCDEF";
    out[0] = h[(b >> 4) & 0xF];
    out[1] = h[b & 0xF];
}

static VOID FormatUUID(CHAR* dst, SIZE_T dstSz, const UCHAR* u) {
    CHAR buf[48];
    int p = 0;
    ByteToHex(u[3], &buf[p]); p += 2;
    ByteToHex(u[2], &buf[p]); p += 2;
    ByteToHex(u[1], &buf[p]); p += 2;
    ByteToHex(u[0], &buf[p]); p += 2;
    buf[p++] = '-';
    ByteToHex(u[5], &buf[p]); p += 2;
    ByteToHex(u[4], &buf[p]); p += 2;
    buf[p++] = '-';
    ByteToHex(u[7], &buf[p]); p += 2;
    ByteToHex(u[6], &buf[p]); p += 2;
    buf[p++] = '-';
    ByteToHex(u[8], &buf[p]); p += 2;
    ByteToHex(u[9], &buf[p]); p += 2;
    buf[p++] = '-';
    for (int i = 10; i < 16; i++) {
        ByteToHex(u[i], &buf[p]); p += 2;
    }
    buf[p] = '\0';
    RtlStringCbCopyA(dst, dstSz, buf);
}

static VOID GenAllIDs() {
    LARGE_INTEGER perf;
    perf = KeQueryPerformanceCounter(NULL);
    g_Rng = perf.LowPart ^ perf.HighPart ^ 0x5A3C1E7D;

    RtlStringCbCopyA(g_DS, sizeof(g_DS), "WD-WMAZA");
    RandHex(g_DS + 8, 9);

    RtlStringCbCopyA(g_MN, sizeof(g_MN), "WDC WD10EZEX-");
    RandHex(g_MN + 14, 9);

    RandHex(g_FR, 9);

    RtlStringCbCopyA(g_BS, sizeof(g_BS), "BIOS-");
    RandSerial(g_BS + 5, 13);

    RtlStringCbCopyA(g_MB, sizeof(g_MB), "BS-");
    RandSerial(g_MB + 3, 13);

    for (int i = 0; i < 16; i++) g_UU[i] = (UCHAR)(Rng() & 0xFF);

    g_MC[0] = 0x02;
    for (int i = 1; i < 6; i++) g_MC[i] = (UCHAR)(Rng() & 0xFF);

    Rng();
    g_VS = g_Rng;

    RtlStringCbCopyA(g_GP, sizeof(g_GP), "GPU-");
    RandHex(g_GP + 4, 13);
}

// ==================== LOG ====================

static VOID WriteLog() {
    RtlCopyMemory(g_Log.Sig, "HWIDLOG", 8);
    RtlCopyMemory(g_Log.FDs, g_DS, 64);
    RtlCopyMemory(g_Log.FBs, g_BS, 64);
    RtlCopyMemory(g_Log.FMs, g_MB, 64);
    RtlCopyMemory(g_Log.FMc, g_MC, 6);
    g_Log.FVs = g_VS;
    RtlCopyMemory(g_Log.FGp, g_GP, 64);
    RtlCopyMemory(g_Log.FMn, g_MN, 48);
    RtlCopyMemory(g_Log.FFr, g_FR, 16);

    FormatUUID(g_Log.FUu, 48, g_UU);

    UNICODE_STRING fp;
    OBJECT_ATTRIBUTES oa;
    IO_STATUS_BLOCK io;
    HANDLE hf;

    RtlInitUnicodeString(&fp, L"\\??\\C:\\ProgramData\\hwid_log.bin");
    InitializeObjectAttributes(&oa, &fp, OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE, NULL, NULL);

    if (NT_SUCCESS(ZwCreateFile(&hf, GENERIC_WRITE | SYNCHRONIZE, &oa, &io,
            NULL, FILE_ATTRIBUTE_HIDDEN | FILE_ATTRIBUTE_SYSTEM, 0, FILE_OVERWRITE_IF,
            FILE_SYNCHRONOUS_IO_NONALERT, NULL, 0))) {
        ZwWriteFile(hf, NULL, NULL, NULL, &io, &g_Log, sizeof(IDLOG), NULL, NULL);
        ZwClose(hf);
    }
    g_Logged = TRUE;
}

// ==================== SMBIOS SPOOFING ====================

static VOID SpoofSMBIOS(PUCHAR buffer, ULONG length) {
    if (length < sizeof(SMBIOS_RAW)) return;
    SMBIOS_RAW* raw = (SMBIOS_RAW*)buffer;
    PUCHAR data = raw->Data;
    PUCHAR end = data + raw->Length;

    while (data < end) {
        SMBIOS_HDR* hdr = (SMBIOS_HDR*)data;
        if (data + hdr->Length > end) break;
        PUCHAR strings = data + hdr->Length;
        if (strings >= end) break;

        if (hdr->Type == 0 && hdr->Length >= 0x12) {
            UCHAR idx = data[0x05];
            UCHAR num = 1;
            PUCHAR sp = strings;
            while (sp < end - 1 && !(sp[0] == 0 && sp[1] == 0)) {
                SIZE_T sl = strlen((char*)sp);
                if (sl > 0 && num == idx) {
                    RtlZeroMemory(sp, sl);
                    RtlCopyMemory(sp, g_FR, min(strlen(g_FR), sl));
                }
                sp += sl + 1; num++;
            }
        }

        if (hdr->Type == 1 && hdr->Length >= 0x19) {
            if (data + 0x08 + 16 <= end) {
                if (!g_Logged)
                    FormatUUID(g_Log.OUu, 48, &data[8]);
                RtlCopyMemory(data + 0x08, g_UU, 16);
            }
            UCHAR idx = data[0x07];
            UCHAR num = 1;
            PUCHAR sp = strings;
            while (sp < end - 1 && !(sp[0] == 0 && sp[1] == 0)) {
                SIZE_T sl = strlen((char*)sp);
                if (sl > 0 && num == idx) {
                    RtlZeroMemory(sp, sl);
                    RtlCopyMemory(sp, g_BS, min(strlen(g_BS), sl));
                }
                sp += sl + 1; num++;
            }
        }

        if (hdr->Type == 2 && hdr->Length >= 0x08) {
            UCHAR idx = data[0x07];
            UCHAR num = 1;
            PUCHAR sp = strings;
            while (sp < end - 1 && !(sp[0] == 0 && sp[1] == 0)) {
                SIZE_T sl = strlen((char*)sp);
                if (sl > 0 && num == idx) {
                    if (!g_Logged) RtlCopyMemory(g_Log.OMs, sp, min(sl, 63));
                    RtlZeroMemory(sp, sl);
                    RtlCopyMemory(sp, g_MB, min(strlen(g_MB), sl));
                }
                sp += sl + 1; num++;
            }
        }

        if (hdr->Type == 3 && hdr->Length >= 0x09) {
            UCHAR idx = data[0x07];
            UCHAR num = 1;
            PUCHAR sp = strings;
            while (sp < end - 1 && !(sp[0] == 0 && sp[1] == 0)) {
                SIZE_T sl = strlen((char*)sp);
                if (sl > 0 && num == idx) {
                    RtlZeroMemory(sp, sl);
                    RtlCopyMemory(sp, g_MB, min(strlen(g_MB), sl));
                }
                sp += sl + 1; num++;
            }
        }

        PUCHAR next = strings;
        while (next < end - 1 && !(next[0] == 0 && next[1] == 0)) next++;
        data = next + 2;
    }
}

// ==================== DISK HOOK ====================

NTSTATUS HkDisk(PDEVICE_OBJECT dev, PIRP irp);

static VOID SpoofStorageQP(PVOID buf, ULONG_PTR len) {
    PSTORAGE_DEVICE_DESCRIPTOR d = (PSTORAGE_DEVICE_DESCRIPTOR)buf;

    if (d->SerialNumberOffset > 0 && d->SerialNumberOffset < len) {
        PCHAR s = (PCHAR)((PUCHAR)d + d->SerialNumberOffset);
        SIZE_T ml = len - d->SerialNumberOffset;
        if (!g_Logged) RtlCopyMemory(g_Log.ODs, s, min(strlen(s), 63));
        if (ml > strlen(g_DS)) { RtlZeroMemory(s, ml); RtlCopyMemory(s, g_DS, strlen(g_DS)); }
    }
    if (d->ProductIdOffset > 0 && d->ProductIdOffset < len) {
        PCHAR s = (PCHAR)((PUCHAR)d + d->ProductIdOffset);
        SIZE_T ml = len - d->ProductIdOffset;
        if (!g_Logged) RtlCopyMemory(g_Log.OMn, s, min(strlen(s), 47));
        if (ml > strlen(g_MN)) { RtlZeroMemory(s, ml); RtlCopyMemory(s, g_MN, strlen(g_MN)); }
    }
    if (d->ProductRevisionOffset > 0 && d->ProductRevisionOffset < len) {
        PCHAR s = (PCHAR)((PUCHAR)d + d->ProductRevisionOffset);
        SIZE_T ml = len - d->ProductRevisionOffset;
        if (!g_Logged) RtlCopyMemory(g_Log.OFr, s, min(strlen(s), 15));
        if (ml > strlen(g_FR)) { RtlZeroMemory(s, ml); RtlCopyMemory(s, g_FR, strlen(g_FR)); }
    }
}

static VOID SpoofATA(PVOID buf, ULONG len) {
    if (len < 512) return;
    IDENT_DATA* id = (IDENT_DATA*)buf;
    CHAR fs[20], fm[40], ff[8];
    RtlZeroMemory(fs, 20); RtlZeroMemory(fm, 40); RtlZeroMemory(ff, 8);

    SIZE_T sl = min(strlen(g_DS), 20);
    RtlCopyMemory(fs, g_DS, sl);
    for (SIZE_T i = sl; i < 20; i++) fs[i] = ' ';

    SIZE_T ml = min(strlen(g_MN), 40);
    RtlCopyMemory(fm, g_MN, ml);
    for (SIZE_T i = ml; i < 40; i++) fm[i] = ' ';

    SIZE_T fl = min(strlen(g_FR), 8);
    RtlCopyMemory(ff, g_FR, fl);
    for (SIZE_T i = fl; i < 8; i++) ff[i] = ' ';

    SwapBytes(fs, 20); SwapBytes(fm, 40); SwapBytes(ff, 8);
    RtlCopyMemory(id->Serial, fs, 20);
    RtlCopyMemory(id->Model, fm, 40);
    RtlCopyMemory(id->FwRev, ff, 8);
}

static VOID SpoofSMART(PVOID buf, ULONG len) {
    if (len > 24 + 512) SpoofATA((PUCHAR)buf + 24, 512);
}

NTSTATUS HkDisk(PDEVICE_OBJECT dev, PIRP irp) {
    PIO_STACK_LOCATION sp = IoGetCurrentIrpStackLocation(irp);
    ULONG code = sp->Parameters.DeviceIoControl.IoControlCode;

    if (code == IOCTL_STORAGE_QUERY_PROPERTY) {
        PVOID b = irp->AssociatedIrp.SystemBuffer;
        ULONG savedPropId = (ULONG)-1;
        if (b) savedPropId = ((PSTORAGE_PROPERTY_QUERY)b)->PropertyId;

        NTSTATUS st = CallOrig(&g_hDisk, dev, irp);
        if (NT_SUCCESS(st) && savedPropId == StorageDeviceProperty &&
            irp->IoStatus.Information > sizeof(STORAGE_DEVICE_DESCRIPTOR) && b) {
            SpoofStorageQP(b, irp->IoStatus.Information);
        }
        return st;
    }
    if (code == IO_SMART) {
        NTSTATUS st = CallOrig(&g_hDisk, dev, irp);
        if (NT_SUCCESS(st) && irp->IoStatus.Information > 0 && irp->AssociatedIrp.SystemBuffer)
            SpoofSMART(irp->AssociatedIrp.SystemBuffer, (ULONG)irp->IoStatus.Information);
        return st;
    }
    if (code == IO_ATA || code == IO_ATA_D) {
        NTSTATUS st = CallOrig(&g_hDisk, dev, irp);
        if (NT_SUCCESS(st) && irp->IoStatus.Information > 0 && irp->AssociatedIrp.SystemBuffer) {
            PATA_PT a = (PATA_PT)irp->AssociatedIrp.SystemBuffer;
            if (a->CurTF[6] == ID_ATA_IDENT && a->DataLen >= 512)
                SpoofATA((PUCHAR)a + a->DataOff, a->DataLen);
        }
        return st;
    }
    if (code == IO_NVME_CMD) {
        NTSTATUS st = CallOrig(&g_hDisk, dev, irp);
        if (NT_SUCCESS(st) && irp->IoStatus.Information > 64 && irp->AssociatedIrp.SystemBuffer) {
            PUCHAR d = (PUCHAR)irp->AssociatedIrp.SystemBuffer;
            SIZE_T slen = min(strlen(g_DS), 20);
            RtlZeroMemory(d + 44, 20);
            RtlCopyMemory(d + 44, g_DS, slen);
        }
        return st;
    }
    return CallOrig(&g_hDisk, dev, irp);
}

// ==================== NDIS HOOK ====================

NTSTATUS HkNdis(PDEVICE_OBJECT dev, PIRP irp);

NTSTATUS HkNdis(PDEVICE_OBJECT dev, PIRP irp) {
    PIO_STACK_LOCATION sp = IoGetCurrentIrpStackLocation(irp);

    if (sp->MajorFunction == IRP_MJ_INTERNAL_DEVICE_CONTROL ||
        sp->MajorFunction == IRP_MJ_DEVICE_CONTROL) {
        NTSTATUS st = CallOrig(&g_hNdis, dev, irp);
        if (NT_SUCCESS(st) && irp->IoStatus.Information >= 6) {
            PUCHAR mac = (PUCHAR)irp->AssociatedIrp.SystemBuffer;
            if (mac) {
                BOOLEAN ok = FALSE;
                for (int i = 0; i < 6; i++) { if (mac[i] != 0 && mac[i] != 0xFF) { ok = TRUE; break; } }
                if (ok) {
                    if (!g_Logged) RtlCopyMemory(g_Log.OMc, mac, 6);
                    RtlCopyMemory(mac, g_MC, 6);
                }
            }
        }
        return st;
    }
    return CallOrig(&g_hNdis, dev, irp);
}

// ==================== FS HOOK (VOLUME SERIAL) ====================

NTSTATUS HkFs(PDEVICE_OBJECT dev, PIRP irp);

NTSTATUS HkFs(PDEVICE_OBJECT dev, PIRP irp) {
    PIO_STACK_LOCATION sp = IoGetCurrentIrpStackLocation(irp);
    NTSTATUS st = CallOrig(&g_hFs, dev, irp);

    if (NT_SUCCESS(st) &&
        sp->Parameters.QueryVolume.FsInformationClass == 1 &&
        irp->IoStatus.Information >= sizeof(FS_VOL_INFO)) {
        FS_VOL_INFO* vi = (FS_VOL_INFO*)irp->AssociatedIrp.SystemBuffer;
        if (vi) {
            if (!g_Logged) g_Log.OVs = vi->SerialNumber;
            vi->SerialNumber = g_VS;
        }
    }
    return st;
}

// ==================== SMBIOS QUERY HOOK ====================

NTSTATUS NTAPI HkNtQuerySysInfo(ULONG Class, PVOID Info, ULONG Length, PULONG RetLength) {
    FnNtQuerySysInfo orig = (FnNtQuerySysInfo)g_hSysInfo.Trampoline;
    NTSTATUS st = orig(Class, Info, Length, RetLength);

    if (NT_SUCCESS(st) && Class == 76 && Info && g_SpoofedSMBIOS) {
        __try {
            FW_TABLE_INFO* fi = (FW_TABLE_INFO*)Info;
            if (fi->ProviderSignature == 'RSMB' && fi->Action == 1 && fi->TableBufferLength > 0) {
                ULONG copyLen = fi->TableBufferLength < g_SpoofedSMBIOSLen
                    ? fi->TableBufferLength : g_SpoofedSMBIOSLen;
                RtlCopyMemory(fi->TableBuffer, g_SpoofedSMBIOS, copyLen);
            }
        } __except (EXCEPTION_EXECUTE_HANDLER) { }
    }

    return st;
}

// ==================== REGISTRY SPOOFING ====================

static VOID RegReadStr(HANDLE hk, PCWSTR name, PCHAR dst, SIZE_T dstSz) {
    UNICODE_STRING vn;
    RtlInitUnicodeString(&vn, name);
    UCHAR buf[512];
    ULONG len = 0;
    NTSTATUS st = ZwQueryValueKey(hk, &vn, KeyValuePartialInformation, buf, sizeof(buf), &len);
    if (NT_SUCCESS(st)) {
        PKEY_VALUE_PARTIAL_INFORMATION kv = (PKEY_VALUE_PARTIAL_INFORMATION)buf;
        if (kv->Type == REG_SZ && kv->DataLength > sizeof(WCHAR)) {
            UNICODE_STRING us;
            us.Buffer = (PWCH)kv->Data;
            us.Length = (USHORT)(kv->DataLength - sizeof(WCHAR));
            us.MaximumLength = (USHORT)kv->DataLength;
            ANSI_STRING as;
            if (NT_SUCCESS(RtlUnicodeStringToAnsiString(&as, &us, TRUE))) {
                SIZE_T copyLen = (SIZE_T)as.Length < dstSz - 1 ? (SIZE_T)as.Length : dstSz - 1;
                RtlCopyMemory(dst, as.Buffer, copyLen);
                dst[copyLen] = '\0';
                RtlFreeAnsiString(&as);
            }
        }
    }
}

static VOID RegSetStr(HANDLE hk, PCWSTR name, PCHAR val) {
    UNICODE_STRING vn; ANSI_STRING av; UNICODE_STRING uv;
    RtlInitUnicodeString(&vn, name);
    RtlInitAnsiString(&av, val);
    if (NT_SUCCESS(RtlAnsiStringToUnicodeString(&uv, &av, TRUE))) {
        ZwSetValueKey(hk, &vn, 0, REG_SZ, uv.Buffer, uv.Length + sizeof(WCHAR));
        RtlFreeUnicodeString(&uv);
    }
}

static VOID SpoofRegistry() {
    UNICODE_STRING kp; OBJECT_ATTRIBUTES oa; HANDLE hk; NTSTATUS st;

    RtlInitUnicodeString(&kp, L"\\Registry\\Machine\\HARDWARE\\DESCRIPTION\\System\\BIOS");
    InitializeObjectAttributes(&oa, &kp, OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE, NULL, NULL);
    st = ZwOpenKey(&hk, KEY_SET_VALUE | KEY_QUERY_VALUE, &oa);
    if (NT_SUCCESS(st)) {
        if (!g_Logged) {
            RegReadStr(hk, L"SystemSerialNumber", g_Log.OBs, 64);
            RegReadStr(hk, L"BaseBoardSerialNumber", g_Log.OMs, 64);
        }
        RegReadStr(hk, L"BIOSVersion", g_OrigBV, 64);
        RegReadStr(hk, L"SystemProductName", g_OrigPN, 48);
        RegSetStr(hk, L"SystemSerialNumber", g_BS);
        RegSetStr(hk, L"BaseBoardSerialNumber", g_MB);
        RegSetStr(hk, L"BIOSVersion", g_FR);
        RegSetStr(hk, L"SystemProductName", g_MN);
        ZwClose(hk);
    }

    RtlInitUnicodeString(&kp,
        L"\\Registry\\Machine\\SYSTEM\\CurrentControlSet\\Control\\Class\\{4d36e968-e325-11ce-bfc1-08002be10318}\\0000");
    InitializeObjectAttributes(&oa, &kp, OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE, NULL, NULL);
    st = ZwOpenKey(&hk, KEY_SET_VALUE | KEY_QUERY_VALUE, &oa);
    if (NT_SUCCESS(st)) {
        if (!g_Logged) {
            RegReadStr(hk, L"HardwareInformation.AdapterString", g_Log.OGp, 64);
        }
        RegSetStr(hk, L"HardwareInformation.AdapterString", g_GP);
        ZwClose(hk);
    }
}

// ==================== MAC REGISTRY SPOOFING ====================

static VOID BuildNICKeyPath(WCHAR* out, int idx) {
    static const WCHAR base[] =
        L"\\Registry\\Machine\\SYSTEM\\CurrentControlSet\\Control\\Class\\"
        L"{4d36e972-e325-11ce-bfc1-08002be10318}\\";
    SIZE_T len = sizeof(base) / sizeof(WCHAR) - 1;
    RtlCopyMemory(out, base, len * sizeof(WCHAR));
    out[len]     = L'0';
    out[len + 1] = L'0';
    out[len + 2] = (WCHAR)(L'0' + (idx / 10));
    out[len + 3] = (WCHAR)(L'0' + (idx % 10));
    out[len + 4] = L'\0';
}

static VOID SpoofMACRegistry() {
    static const CHAR hex[] = "0123456789ABCDEF";
    CHAR macStr[13];
    for (int j = 0; j < 6; j++) {
        macStr[j * 2]     = hex[(g_MC[j] >> 4) & 0xF];
        macStr[j * 2 + 1] = hex[g_MC[j] & 0xF];
    }
    macStr[12] = '\0';

    WCHAR keyPath[256];
    UNICODE_STRING kp;
    OBJECT_ATTRIBUTES oa;
    HANDLE hk;

    for (int i = 0; i < 20; i++) {
        BuildNICKeyPath(keyPath, i);
        RtlInitUnicodeString(&kp, keyPath);
        InitializeObjectAttributes(&oa, &kp, OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE, NULL, NULL);
        if (NT_SUCCESS(ZwOpenKey(&hk, KEY_SET_VALUE, &oa))) {
            RegSetStr(hk, L"NetworkAddress", macStr);
            ZwClose(hk);
        }
    }
}

// ==================== REGISTRY REVERT ====================

static VOID RevertRegistry() {
    UNICODE_STRING kp; OBJECT_ATTRIBUTES oa; HANDLE hk; NTSTATUS st;

    RtlInitUnicodeString(&kp, L"\\Registry\\Machine\\HARDWARE\\DESCRIPTION\\System\\BIOS");
    InitializeObjectAttributes(&oa, &kp, OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE, NULL, NULL);
    st = ZwOpenKey(&hk, KEY_SET_VALUE, &oa);
    if (NT_SUCCESS(st)) {
        if (g_Log.OBs[0]) RegSetStr(hk, L"SystemSerialNumber", g_Log.OBs);
        if (g_Log.OMs[0]) RegSetStr(hk, L"BaseBoardSerialNumber", g_Log.OMs);
        if (g_OrigBV[0])  RegSetStr(hk, L"BIOSVersion", g_OrigBV);
        if (g_OrigPN[0])  RegSetStr(hk, L"SystemProductName", g_OrigPN);
        ZwClose(hk);
    }

    RtlInitUnicodeString(&kp,
        L"\\Registry\\Machine\\SYSTEM\\CurrentControlSet\\Control\\Class\\{4d36e968-e325-11ce-bfc1-08002be10318}\\0000");
    InitializeObjectAttributes(&oa, &kp, OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE, NULL, NULL);
    st = ZwOpenKey(&hk, KEY_SET_VALUE, &oa);
    if (NT_SUCCESS(st)) {
        if (g_Log.OGp[0]) RegSetStr(hk, L"HardwareInformation.AdapterString", g_Log.OGp);
        ZwClose(hk);
    }
}

static VOID RevertMACRegistry() {
    WCHAR keyPath[256];
    UNICODE_STRING kp, vn;
    OBJECT_ATTRIBUTES oa;
    HANDLE hk;

    RtlInitUnicodeString(&vn, L"NetworkAddress");

    for (int i = 0; i < 20; i++) {
        BuildNICKeyPath(keyPath, i);
        RtlInitUnicodeString(&kp, keyPath);
        InitializeObjectAttributes(&oa, &kp, OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE, NULL, NULL);
        if (NT_SUCCESS(ZwOpenKey(&hk, KEY_SET_VALUE, &oa))) {
            ZwDeleteValueKey(hk, &vn);
            ZwClose(hk);
        }
    }
}

// ==================== REVERT THREAD ====================

static VOID RevertThread(PVOID context) {
    UNREFERENCED_PARAMETER(context);
    KeWaitForSingleObject(g_pRevertEvent, Executive, KernelMode, FALSE, NULL);

    HookRemove(&g_hDisk);
    HookRemove(&g_hNdis);
    HookRemove(&g_hFs);
    HookRemove(&g_hSysInfo);

    RevertRegistry();
    RevertMACRegistry();

    PsTerminateSystemThread(STATUS_SUCCESS);
}

// ==================== ENTRY ====================

NTSTATUS DriverEntry(PDRIVER_OBJECT DriverObject, PUNICODE_STRING RegistryPath) {
    UNREFERENCED_PARAMETER(RegistryPath);
    UNREFERENCED_PARAMETER(DriverObject);

    GenAllIDs();

    PVOID fn = NULL;
    const WCHAR* drvs[] = { L"\\Driver\\disk", L"\\Driver\\storahci", L"\\Driver\\stornvme" };
    for (int i = 0; i < 3; i++) {
        fn = FindDispatch(drvs[i], IRP_MJ_DEVICE_CONTROL);
        if (fn) break;
    }
    if (fn) HookInstall(fn, HkDisk, &g_hDisk);

    fn = FindDispatch(L"\\Driver\\ndis", IRP_MJ_DEVICE_CONTROL);
    if (!fn) fn = FindDispatch(L"\\Driver\\ndis", IRP_MJ_INTERNAL_DEVICE_CONTROL);
    if (fn) HookInstall(fn, HkNdis, &g_hNdis);

    fn = FindDispatch(L"\\FileSystem\\Ntfs", IRP_MJ_QUERY_VOLUME_INFORMATION);
    if (fn) HookInstall(fn, HkFs, &g_hFs);

    {
        ULONG needed = 0;
        FW_TABLE_INFO probe = {0};
        probe.ProviderSignature = 'RSMB';
        probe.Action = 1;
        ZwQuerySystemInformation(76, &probe, sizeof(probe), &needed);
        if (needed > 0) {
            FW_TABLE_INFO* fi =
                (FW_TABLE_INFO*)ExAllocatePoolWithTag(NonPagedPool, needed, 'bmsR');
            if (fi) {
                RtlZeroMemory(fi, needed);
                fi->ProviderSignature = 'RSMB';
                fi->Action = 1;
                NTSTATUS st = ZwQuerySystemInformation(76, fi, needed, &needed);
                if (NT_SUCCESS(st) && fi->TableBufferLength > 0) {
                    SpoofSMBIOS(fi->TableBuffer, fi->TableBufferLength);
                    g_SpoofedSMBIOSLen = fi->TableBufferLength;
                    g_SpoofedSMBIOS = (PUCHAR)ExAllocatePoolWithTag(
                        NonPagedPool, fi->TableBufferLength, 'bmsS');
                    if (g_SpoofedSMBIOS) {
                        RtlCopyMemory(g_SpoofedSMBIOS, fi->TableBuffer, fi->TableBufferLength);
                    }
                }
                ExFreePoolWithTag(fi, 'bmsR');
            }
        }

        UNICODE_STRING fnName;
        RtlInitUnicodeString(&fnName, L"NtQuerySystemInformation");
        PVOID ntQsi = MmGetSystemRoutineAddress(&fnName);
        if (ntQsi && g_SpoofedSMBIOS) {
            HookInstall(ntQsi, HkNtQuerySysInfo, &g_hSysInfo);
        }
    }

    SpoofRegistry();
    SpoofMACRegistry();

    WriteLog();

    {
        UNICODE_STRING evtName;
        RtlInitUnicodeString(&evtName, L"\\BaseNamedObjects\\HWIDSpooferRevert");
        OBJECT_ATTRIBUTES evtOa;
        InitializeObjectAttributes(&evtOa, &evtName, OBJ_CASE_INSENSITIVE, NULL, NULL);
        HANDLE hEvt;
        if (NT_SUCCESS(ZwCreateEvent(&hEvt, EVENT_ALL_ACCESS, &evtOa,
                NotificationEvent, FALSE))) {
            ObReferenceObjectByHandle(hEvt, EVENT_ALL_ACCESS,
                *ExEventObjectType, KernelMode, (PVOID*)&g_pRevertEvent, NULL);
            ZwClose(hEvt);

            KeClearEvent(g_pRevertEvent);

            HANDLE hThread;
            PsCreateSystemThread(&hThread, THREAD_ALL_ACCESS,
                NULL, NULL, NULL, RevertThread, NULL);
            ZwClose(hThread);
        }
    }

    return STATUS_SUCCESS;
}
