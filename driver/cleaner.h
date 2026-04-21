/*
 * cleaner.h - Trace cleaning for manually-mapped driver.
 *
 * Removes evidence of iqvw64e.sys loading from:
 *   1. PiDDB Cache Table (Plug and Play Database)
 *   2. MmUnloadedDrivers array
 *   3. DriverObject (unlink from PsLoadedModuleList, erase PE headers)
 *
 * Pattern adapted from External_Rust_AI driver_stealth_mechanisms.md.
 * All functions are header-only for simplicity in a manually-mapped driver.
 */

#ifndef HWID_CLEANER_H
#define HWID_CLEANER_H

#include <ntifs.h>
#include <ntimage.h>
#include <intrin.h>

/* ----------------------------------------------------------------
 * Undocumented imports
 * ---------------------------------------------------------------- */

NTKERNELAPI PPEB PsGetProcessPeb(IN PEPROCESS Process);

#ifndef _ZWQUERYSYSTEMINFORMATION_DECLARED
#define _ZWQUERYSYSTEMINFORMATION_DECLARED
NTSYSCALLAPI NTSTATUS NTAPI ZwQuerySystemInformation(
    ULONG SystemInformationClass, PVOID SystemInformation,
    ULONG SystemInformationLength, PULONG ReturnLength);
#endif

typedef struct _RTL_PROCESS_MODULE_INFORMATION {
    HANDLE Section;
    PVOID  MappedBase;
    PVOID  ImageBase;
    ULONG  ImageSize;
    ULONG  Flags;
    USHORT LoadOrderIndex;
    USHORT InitOrderIndex;
    USHORT LoadCount;
    USHORT OffsetToFileName;
    CHAR   FullPathName[256];
} RTL_PROCESS_MODULE_INFORMATION, *PRTL_PROCESS_MODULE_INFORMATION;

typedef struct _RTL_PROCESS_MODULES {
    ULONG NumberOfModules;
    RTL_PROCESS_MODULE_INFORMATION Modules[1];
} RTL_PROCESS_MODULES, *PRTL_PROCESS_MODULES;

/* PiDDB cache entry structure */
typedef struct _PIDDB_CACHE_ENTRY {
    LIST_ENTRY      List;
    UNICODE_STRING  DriverName;
    ULONG           TimeDateStamp;
    NTSTATUS        LoadStatus;
    char            _pad[16];
} PIDDB_CACHE_ENTRY;

/* MmUnloadedDrivers entry */
typedef struct _MM_UNLOADED_DRIVER {
    UNICODE_STRING Name;
    PVOID          ModuleStart;
    PVOID          ModuleEnd;
    LARGE_INTEGER  UnloadTime;
} MM_UNLOADED_DRIVER, *PMM_UNLOADED_DRIVER;

/* Imports for AVL table operations */
NTKERNELAPI PVOID NTAPI RtlLookupElementGenericTableAvl(
    PRTL_AVL_TABLE Table, PVOID Buffer);
NTKERNELAPI BOOLEAN NTAPI RtlDeleteElementGenericTableAvl(
    PRTL_AVL_TABLE Table, PVOID Buffer);

/* iqvw64e.sys timestamp used for PiDDB lookup */
#define IQVW64E_TIMESTAMP 0x5284EAC3

/* ----------------------------------------------------------------
 * Pattern scanner
 * ---------------------------------------------------------------- */

static PVOID Cleaner_FindPattern(PVOID base, SIZE_T size,
    const UCHAR* pattern, const CHAR* mask)
{
    SIZE_T patLen = 0;
    while (mask[patLen]) patLen++;

    if (patLen == 0 || patLen > size) return NULL;

    PUCHAR b = (PUCHAR)base;
    for (SIZE_T i = 0; i <= size - patLen; i++) {
        BOOLEAN found = TRUE;
        for (SIZE_T j = 0; j < patLen; j++) {
            if (mask[j] != '?' && b[i + j] != pattern[j]) {
                found = FALSE;
                break;
            }
        }
        if (found) return &b[i];
    }
    return NULL;
}

/* ----------------------------------------------------------------
 * Helper: get ntoskrnl base and size
 * ---------------------------------------------------------------- */

static BOOLEAN Cleaner_GetKernelInfo(PVOID* outBase, ULONG* outSize) {
    ULONG needed = 0;
    ZwQuerySystemInformation(11, NULL, 0, &needed);
    if (needed == 0) return FALSE;

    PRTL_PROCESS_MODULES mods = (PRTL_PROCESS_MODULES)
        ExAllocatePool2(POOL_FLAG_NON_PAGED, needed, 'cLnK');
    if (!mods) return FALSE;

    NTSTATUS st = ZwQuerySystemInformation(11, mods, needed, &needed);
    if (!NT_SUCCESS(st) || mods->NumberOfModules == 0) {
        ExFreePoolWithTag(mods, 'cLnK');
        return FALSE;
    }

    *outBase = mods->Modules[0].ImageBase;
    *outSize = mods->Modules[0].ImageSize;
    ExFreePoolWithTag(mods, 'cLnK');
    return TRUE;
}

/* Resolve RIP-relative address from instruction at 'inst' with offset at
 * position 'offset' and instruction length 'instLen'. */
static PVOID Cleaner_ResolveRelative(PVOID inst, INT offset, INT instLen) {
    PUCHAR p = (PUCHAR)inst;
    INT32 rel = *(INT32*)(p + offset);
    return (PVOID)(p + instLen + rel);
}

/* Find a named section in the kernel PE */
static BOOLEAN Cleaner_FindSection(PVOID kernelBase, const char* name,
    PVOID* outStart, SIZE_T* outSize)
{
    if (!kernelBase) return FALSE;
    PIMAGE_DOS_HEADER dos = (PIMAGE_DOS_HEADER)kernelBase;
    if (dos->e_magic != IMAGE_DOS_SIGNATURE) return FALSE;
    PIMAGE_NT_HEADERS64 nt = (PIMAGE_NT_HEADERS64)((PUCHAR)kernelBase + dos->e_lfanew);
    if (nt->Signature != IMAGE_NT_SIGNATURE) return FALSE;
    PIMAGE_SECTION_HEADER sec = IMAGE_FIRST_SECTION(nt);

    for (USHORT i = 0; i < nt->FileHeader.NumberOfSections; i++) {
        if (strncmp((const char*)sec[i].Name, name, 8) == 0) {
            *outStart = (PVOID)((PUCHAR)kernelBase + sec[i].VirtualAddress);
            *outSize = sec[i].Misc.VirtualSize;
            return TRUE;
        }
    }
    return FALSE;
}

/* ----------------------------------------------------------------
 * 1. Clean PiDDB Cache Table
 * ---------------------------------------------------------------- */

static BOOLEAN Cleaner_CleanPiDDB(PVOID kernelBase, ULONG kernelSize) {
    PVOID pageStart = NULL;
    SIZE_T pageSize = 0;
    if (!Cleaner_FindSection(kernelBase, "PAGE", &pageStart, &pageSize))
        return FALSE;

    /*
     * PiDDBLock pattern:
     * 48 8D 0D ?? ?? ?? ?? E8 ?? ?? ?? ?? 48 8B 0D ?? ?? ?? ?? 33 DB
     *
     * PiDDBCacheTable pattern:
     * 48 8D 0D ?? ?? ?? ?? E8 ?? ?? ?? ?? 3D ?? ?? ?? ?? 0F 83
     */
    static const UCHAR lockPat[] = {
        0x48, 0x8D, 0x0D, 0xCC, 0xCC, 0xCC, 0xCC,
        0xE8, 0xCC, 0xCC, 0xCC, 0xCC,
        0x48, 0x8B, 0x0D, 0xCC, 0xCC, 0xCC, 0xCC,
        0x33, 0xDB
    };
    static const CHAR lockMask[] = "xxx????x????xxx????xx";

    static const UCHAR tablePat[] = {
        0x48, 0x8D, 0x0D, 0xCC, 0xCC, 0xCC, 0xCC,
        0xE8, 0xCC, 0xCC, 0xCC, 0xCC,
        0x3D, 0xCC, 0xCC, 0xCC, 0xCC,
        0x0F, 0x83
    };
    static const CHAR tableMask[] = "xxx????x????x????xx";

    PVOID lockMatch = Cleaner_FindPattern(pageStart, pageSize, lockPat, lockMask);
    PVOID tableMatch = Cleaner_FindPattern(pageStart, pageSize, tablePat, tableMask);

    if (!lockMatch || !tableMatch)
        return FALSE;

    /* Resolve RIP-relative LEA rcx,[rip+disp32] at offset 3, instruction is 7 bytes */
    PERESOURCE PiDDBLock = (PERESOURCE)Cleaner_ResolveRelative(lockMatch, 3, 7);
    PRTL_AVL_TABLE PiDDBCacheTable = (PRTL_AVL_TABLE)Cleaner_ResolveRelative(tableMatch, 3, 7);

    if (!PiDDBLock || !PiDDBCacheTable)
        return FALSE;

    /* Build lookup entry for iqvw64e.sys */
    UNICODE_STRING drvName;
    RtlInitUnicodeString(&drvName, L"iqvw64e.sys");

    PIDDB_CACHE_ENTRY lookupEntry;
    RtlZeroMemory(&lookupEntry, sizeof(lookupEntry));
    lookupEntry.DriverName = drvName;
    lookupEntry.TimeDateStamp = IQVW64E_TIMESTAMP;

    ExAcquireResourceExclusiveLite(PiDDBLock, TRUE);

    PIDDB_CACHE_ENTRY* pFound = (PIDDB_CACHE_ENTRY*)
        RtlLookupElementGenericTableAvl(PiDDBCacheTable, &lookupEntry);

    if (pFound) {
        RemoveEntryList(&pFound->List);
        RtlDeleteElementGenericTableAvl(PiDDBCacheTable, pFound);
    }

    ExReleaseResourceLite(PiDDBLock);
    return TRUE;
}

/* ----------------------------------------------------------------
 * 2. Clean MmUnloadedDrivers
 * ---------------------------------------------------------------- */

static BOOLEAN Cleaner_CleanMmUnloadedDrivers(PVOID kernelBase, ULONG kernelSize) {
    PVOID pageStart = NULL;
    SIZE_T pageSize = 0;
    if (!Cleaner_FindSection(kernelBase, "PAGE", &pageStart, &pageSize))
        return FALSE;

    /*
     * MmUnloadedDrivers pattern:
     * 4C 8B ?? ?? ?? ?? ?? 4C 8B C9 4D 85 ?? 74
     */
    static const UCHAR pat[] = {
        0x4C, 0x8B, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC,
        0x4C, 0x8B, 0xC9,
        0x4D, 0x85, 0xCC,
        0x74
    };
    static const CHAR mask[] = "xx?????xxx??x?";

    PVOID match = Cleaner_FindPattern(pageStart, pageSize, pat, mask);
    if (!match) return FALSE;

    /* Resolve: 4C 8B 05/0D/15/1D/25/2D/35/3D => RIP-relative at offset 3, instLen 7 */
    PMM_UNLOADED_DRIVER* ppDrivers = (PMM_UNLOADED_DRIVER*)
        Cleaner_ResolveRelative(match, 3, 7);
    if (!ppDrivers || !*ppDrivers) return FALSE;

    PMM_UNLOADED_DRIVER drivers = *ppDrivers;
    BOOLEAN cleaned = FALSE;

    /* MmUnloadedDrivers has up to 50 entries */
    for (ULONG i = 0; i < 50; i++) {
        if (drivers[i].Name.Buffer == NULL)
            continue;

        /* Case-insensitive check for iqvw64e */
        UNICODE_STRING target;
        RtlInitUnicodeString(&target, L"iqvw64e.sys");

        if (RtlCompareUnicodeString(&drivers[i].Name, &target, TRUE) == 0) {
            /* Zero out the entry */
            RtlZeroMemory(&drivers[i].Name, sizeof(UNICODE_STRING));
            RtlZeroMemory(&drivers[i], sizeof(MM_UNLOADED_DRIVER));
            cleaned = TRUE;
        }
    }

    return cleaned;
}

/* ----------------------------------------------------------------
 * 3. Hide Driver Object
 * ---------------------------------------------------------------- */

static VOID Cleaner_HideDriverObject(PDRIVER_OBJECT DriverObject) {
    if (!DriverObject) return;

    /* Wipe driver name buffer */
    if (DriverObject->DriverName.Buffer) {
        RtlZeroMemory(DriverObject->DriverName.Buffer,
            DriverObject->DriverName.MaximumLength);
    }

    /* Unlink from PsLoadedModuleList via DriverSection (KLDR_DATA_TABLE_ENTRY) */
    PVOID driverSection = DriverObject->DriverSection;
    if (driverSection) {
        PLIST_ENTRY entry = (PLIST_ENTRY)driverSection;
        PLIST_ENTRY prev = entry->Blink;
        PLIST_ENTRY next = entry->Flink;
        if (prev && next) {
            prev->Flink = next;
            next->Blink = prev;
            entry->Flink = entry;
            entry->Blink = entry;
        }
    }

    /* Erase PE headers at DriverStart */
    if (DriverObject->DriverStart) {
        PIMAGE_DOS_HEADER dos = (PIMAGE_DOS_HEADER)DriverObject->DriverStart;
        __try {
            if (dos->e_magic == IMAGE_DOS_SIGNATURE) {
                PIMAGE_NT_HEADERS64 nt = (PIMAGE_NT_HEADERS64)(
                    (PUCHAR)DriverObject->DriverStart + dos->e_lfanew);
                ULONG headerSize = nt->OptionalHeader.SizeOfHeaders;
                RtlZeroMemory(DriverObject->DriverStart, headerSize);
            }
        } __except (EXCEPTION_EXECUTE_HANDLER) { }
    }

    /* Nullify critical fields */
    DriverObject->DriverSection = NULL;
    DriverObject->DriverInit    = NULL;
    DriverObject->DriverStart   = NULL;
    DriverObject->DriverSize    = 0;
    DriverObject->DriverUnload  = NULL;

    /* Null all MajorFunction pointers */
    for (ULONG i = 0; i <= IRP_MJ_MAXIMUM_FUNCTION; i++) {
        DriverObject->MajorFunction[i] = NULL;
    }
}

/* ----------------------------------------------------------------
 * Master: CleanAllTraces
 * ---------------------------------------------------------------- */

static VOID CleanAllTraces(PDRIVER_OBJECT DriverObject) {
    PVOID kernelBase = NULL;
    ULONG kernelSize = 0;

    if (Cleaner_GetKernelInfo(&kernelBase, &kernelSize)) {
        Cleaner_CleanPiDDB(kernelBase, kernelSize);
        Cleaner_CleanMmUnloadedDrivers(kernelBase, kernelSize);
    }

    Cleaner_HideDriverObject(DriverObject);
}

#endif /* HWID_CLEANER_H */
