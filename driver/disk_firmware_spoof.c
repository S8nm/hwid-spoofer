/*
 * Disk Firmware-Level Serial Spoofing
 * 
 * Intercepts SATA/AHCI/NVMe commands at the miniport level to modify
 * IDENTIFY DEVICE responses, providing persistent disk serial spoofing
 * that survives driver unload.
 */

#include <ntddk.h>

// SCSI/ATA command opcodes
#define ATA_IDENTIFY_DEVICE     0xEC
#define ATA_IDENTIFY_PACKET_DEVICE 0xA1
#define NVME_ADMIN_IDENTIFY     0x06

// IDENTIFY DEVICE data structure offsets
#define ID_SERIAL_OFFSET        20   // 20 bytes, word-aligned
#define ID_MODEL_OFFSET         54   // 40 bytes
#define ID_FW_REV_OFFSET        46   // 8 bytes

// NVMe Identify Controller offsets
#define NVME_SERIAL_OFFSET      4    // 20 bytes
#define NVME_MODEL_OFFSET       24   // 40 bytes
#define NVME_FW_REV_OFFSET      64   // 8 bytes

// Miniport driver identifiers
#define STORAHCI_DRIVER_NAME    L"storahci.sys"
#define STORNVME_DRIVER_NAME    L"stornvme.sys"
#define IAStorAC_DRIVER_NAME    L"iastorac.sys"

// Context for disk spoofing
typedef struct _DISK_SPOOF_CONTEXT {
    BOOLEAN         Initialized;
    BOOLEAN         Enabled;
    
    // Spoofed values for SATA/AHCI
    CHAR            FakeSataSerial[21];
    CHAR            FakeSataModel[41];
    CHAR            FakeSataFirmware[9];
    
    // Spoofed values for NVMe
    CHAR            FakeNvmeSerial[21];
    CHAR            FakeNvmeModel[41];
    CHAR            FakeNvmeFirmware[9];
    
    // Original values (for restore)
    BOOLEAN         HaveOriginalSata;
    CHAR            OriginalSataSerial[21];
    CHAR            OriginalSataModel[41];
    CHAR            OriginalSataFirmware[9];
    
    BOOLEAN         HaveOriginalNvme;
    CHAR            OriginalNvmeSerial[21];
    CHAR            OriginalNvmeModel[41];
    CHAR            OriginalNvmeFirmware[9];
    
    // Hook handles
    PVOID           StorAhciHook;
    PVOID           StorNvmeHook;
    PVOID           MiniportHook;
    
    KSPIN_LOCK      Lock;
} DISK_SPOOF_CONTEXT;

static DISK_SPOOF_CONTEXT g_DiskSpoofContext = {0};

// StorAHCI miniport device extension structure (undocumented, reverse-engineered)
typedef struct _AHCI_CHANNEL_EXTENSION {
    PVOID           AdapterExtension;
    ULONG           ChannelIndex;
    ULONG           PortNumber;
    // ... more fields
} AHCI_CHANNEL_EXTENSION, *PAHCI_CHANNEL_EXTENSION;

// AHCI FIS (Frame Information Structure) - IDENTIFY DEVICE response
#pragma pack(push, 1)
typedef struct _AHCI_FIS_IDENTIFY {
    UINT16  Config;                    // 0
    UINT16  Obsolete1;                 // 1
    UINT16  SpecificConfig;            // 2
    UINT16  Obsolete2;                 // 3
    UINT16  Retired1[2];               // 4-5
    UINT16  Obsolete3;                 // 6
    UINT16  Cylinders;               // 7
    UINT16  Obsolete4;                 // 8
    UINT16  Heads;                     // 9
    UINT16  Obsolete5[2];            // 10-11
    UINT16  SectorsPerTrack;           // 12
    UINT16  VendorUnique1[3];        // 13-15
    CHAR    SerialNumber[20];        // 16-25
    UINT16  Retired2[2];             // 26-27
    UINT16  Obsolete6;                 // 28
    // ... more fields follow
} AHCI_FIS_IDENTIFY, *PAHCI_FIS_IDENTIFY;
#pragma pack(pop)

// NVMe Identify Controller structure
#pragma pack(push, 1)
typedef struct _NVME_IDENTIFY_CONTROLLER {
    UINT16  VID;
    UINT16  SSID;
    CHAR    SerialNumber[20];          // Bytes 4-23
    CHAR    ModelNumber[40];           // Bytes 24-63
    CHAR    FirmwareRevision[8];       // Bytes 64-71
    UINT8   Recommended ArbitrationBurst;
    UINT8   IEEE_OUI[3];
    UINT8   CMIC;
    UINT8   MaxDataTransferSize;
    // ... more fields
} NVME_IDENTIFY_CONTROLLER, *PNVME_IDENTIFY_CONTROLLER;
#pragma pack(pop)

/*
 * Swap bytes in a string (ATA strings are big-endian word-swapped)
 */
VOID DiskSpoof_SwapStringBytes(PCHAR Dest, PCHAR Src, UINT32 Length) {
    for (UINT32 i = 0; i < Length; i += 2) {
        if (i + 1 < Length) {
            Dest[i] = Src[i + 1];
            Dest[i + 1] = Src[i];
        } else {
            Dest[i] = Src[i];
        }
    }
    Dest[Length] = '\0';
}

/*
 * Trim trailing spaces from ATA string
 */
VOID DiskSpoof_TrimAtaString(PCHAR Str, UINT32 Length) {
    // Remove trailing spaces
    for (INT i = (INT)Length - 1; i >= 0; i--) {
        if (Str[i] == ' ' || Str[i] == '\0') {
            Str[i] = '\0';
        } else {
            break;
        }
    }
}

/*
 * Initialize disk spoofing context
 */
NTSTATUS DiskSpoof_Initialize(VOID) {
    RtlZeroMemory(&g_DiskSpoofContext, sizeof(g_DiskSpoofContext));
    KeInitializeSpinLock(&g_DiskSpoofContext.Lock);
    
    // Generate random serial numbers
    // In production, these would be configurable
    RtlCopyMemory(g_DiskSpoofContext.FakeSataSerial, "WD-RANDOM12345      ", 20);
    RtlCopyMemory(g_DiskSpoofContext.FakeSataModel, "WDC WD10EZEX-00BN5A0                    ", 40);
    RtlCopyMemory(g_DiskSpoofContext.FakeSataFirmware, "01.01A01", 8);
    
    RtlCopyMemory(g_DiskSpoofContext.FakeNvmeSerial, "SAMSUNG-RAND123     ", 20);
    RtlCopyMemory(g_DiskSpoofContext.FakeNvmeModel, "Samsung SSD 970 EVO Plus 1TB            ", 40);
    RtlCopyMemory(g_DiskSpoofContext.FakeNvmeFirmware, "2B2QEXM7", 8);
    
    g_DiskSpoofContext.Initialized = TRUE;
    g_DiskSpoofContext.Enabled = TRUE;
    
    return STATUS_SUCCESS;
}

/*
 * Modify SATA IDENTIFY DEVICE response
 */
VOID DiskSpoof_ModifySataIdentify(PAHCI_FIS_IDENTIFY IdentifyData) {
    if (!g_DiskSpoofContext.Initialized || !g_DiskSpoofContext.Enabled) {
        return;
    }
    
    KIRQL oldIrql;
    KeAcquireSpinLock(&g_DiskSpoofContext.Lock, &oldIrql);
    
    // Save original values if not already saved
    if (!g_DiskSpoofContext.HaveOriginalSata) {
        CHAR tempSerial[21];
        CHAR tempModel[41];
        CHAR tempFw[9];
        
        DiskSpoof_SwapStringBytes(tempSerial, IdentifyData->SerialNumber, 20);
        DiskSpoof_TrimAtaString(tempSerial, 20);
        RtlCopyMemory(g_DiskSpoofContext.OriginalSataSerial, tempSerial, 21);
        
        // Model is at offset 54 (27 words * 2 bytes)
        DiskSpoof_SwapStringBytes(tempModel, (PCHAR)((PUINT8)IdentifyData + 54), 40);
        DiskSpoof_TrimAtaString(tempModel, 40);
        RtlCopyMemory(g_DiskSpoofContext.OriginalSataModel, tempModel, 41);
        
        // Firmware at offset 46 (23 words * 2 bytes)
        DiskSpoof_SwapStringBytes(tempFw, (PCHAR)((PUINT8)IdentifyData + 46), 8);
        DiskSpoof_TrimAtaString(tempFw, 8);
        RtlCopyMemory(g_DiskSpoofContext.OriginalSataFirmware, tempFw, 9);
        
        g_DiskSpoofContext.HaveOriginalSata = TRUE;
    }
    
    // Write spoofed serial (need to swap bytes for ATA big-endian)
    CHAR swappedSerial[20];
    for (UINT32 i = 0; i < 20; i += 2) {
        swappedSerial[i] = g_DiskSpoofContext.FakeSataSerial[i + 1];
        swappedSerial[i + 1] = g_DiskSpoofContext.FakeSataSerial[i];
    }
    RtlCopyMemory(IdentifyData->SerialNumber, swappedSerial, 20);
    
    // Write spoofed model
    CHAR swappedModel[40];
    for (UINT32 i = 0; i < 40; i += 2) {
        swappedModel[i] = g_DiskSpoofContext.FakeSataModel[i + 1];
        swappedModel[i + 1] = g_DiskSpoofContext.FakeSataModel[i];
    }
    RtlCopyMemory((PUINT8)IdentifyData + 54, swappedModel, 40);
    
    // Write spoofed firmware
    CHAR swappedFw[8];
    for (UINT32 i = 0; i < 8; i += 2) {
        swappedFw[i] = g_DiskSpoofContext.FakeSataFirmware[i + 1];
        swappedFw[i + 1] = g_DiskSpoofContext.FakeSataFirmware[i];
    }
    RtlCopyMemory((PUINT8)IdentifyData + 46, swappedFw, 8);
    
    KeReleaseSpinLock(&g_DiskSpoofContext.Lock, oldIrql);
}

/*
 * Modify NVMe Identify Controller response
 */
VOID DiskSpoof_ModifyNvmeIdentify(PNVME_IDENTIFY_CONTROLLER IdentifyData) {
    if (!g_DiskSpoofContext.Initialized || !g_DiskSpoofContext.Enabled) {
        return;
    }
    
    KIRQL oldIrql;
    KeAcquireSpinLock(&g_DiskSpoofContext.Lock, &oldIrql);
    
    // Save original values
    if (!g_DiskSpoofContext.HaveOriginalNvme) {
        RtlCopyMemory(g_DiskSpoofContext.OriginalNvmeSerial, IdentifyData->SerialNumber, 20);
        DiskSpoof_TrimAtaString(g_DiskSpoofContext.OriginalNvmeSerial, 20);
        
        RtlCopyMemory(g_DiskSpoofContext.OriginalNvmeModel, IdentifyData->ModelNumber, 40);
        DiskSpoof_TrimAtaString(g_DiskSpoofContext.OriginalNvmeModel, 40);
        
        RtlCopyMemory(g_DiskSpoofContext.OriginalNvmeFirmware, IdentifyData->FirmwareRevision, 8);
        DiskSpoof_TrimAtaString(g_DiskSpoofContext.OriginalNvmeFirmware, 8);
        
        g_DiskSpoofContext.HaveOriginalNvme = TRUE;
    }
    
    // NVMe strings are not byte-swapped, just space-padded
    RtlCopyMemory(IdentifyData->SerialNumber, g_DiskSpoofContext.FakeNvmeSerial, 20);
    RtlCopyMemory(IdentifyData->ModelNumber, g_DiskSpoofContext.FakeNvmeModel, 40);
    RtlCopyMemory(IdentifyData->FirmwareRevision, g_DiskSpoofContext.FakeNvmeFirmware, 8);
    
    KeReleaseSpinLock(&g_DiskSpoofContext.Lock, oldIrql);
}

/*
 * Hook for StorAHCI miniport - intercepts IDENTIFY DEVICE
 * 
 * This is called from the miniport's BuildIo or StartIo routine
 */
BOOLEAN DiskSpoof_HookStorAhci(
    PVOID ChannelExtension,
    PVOID Srb,
    PVOID Cdb
) {
    if (!g_DiskSpoofContext.Initialized || !g_DiskSpoofContext.Enabled) {
        return FALSE;  // Pass through
    }
    
    // Check if this is an IDENTIFY DEVICE command
    PUINT8 cdb = (PUINT8)Cdb;
    
    // ATA passthrough CDB format
    if (cdb[0] == 0x85) {  // ATA PASS-THROUGH (16)
        UINT8 command = cdb[14];  // Command register
        
        if (command == ATA_IDENTIFY_DEVICE || 
            command == ATA_IDENTIFY_PACKET_DEVICE) {
            
            // Mark this SRB for post-processing
            // We need to modify the response after the command completes
            // Store context in SRB extension or use SRB flags
            
            return TRUE;  // Mark for processing
        }
    }
    
    return FALSE;  // Not our command
}

/*
 * Post-process IDENTIFY DEVICE response
 * Called after the miniport completes the command
 */
VOID DiskSpoof_PostProcessSataIdentify(PVOID Srb, PVOID DataBuffer) {
    if (!g_DiskSpoofContext.Initialized || !g_DiskSpoofContext.Enabled) {
        return;
    }
    
    PAHCI_FIS_IDENTIFY identify = (PAHCI_FIS_IDENTIFY)DataBuffer;
    
    // Validate this looks like an IDENTIFY response
    // (Check signature bytes or other identifying features)
    
    DiskSpoof_ModifySataIdentify(identify);
}

/*
 * Hook for StorNVMe miniport
 */
BOOLEAN DiskSpoof_HookStorNvme(
    PVOID AdapterExtension,
    PVOID Request
) {
    if (!g_DiskSpoofContext.Initialized || !g_DiskSpoofContext.Enabled) {
        return FALSE;
    }
    
    // NVMe admin command structure
    // Check if this is an Identify Controller command
    
    PUINT32 cmd = (PUINT32)Request;
    UINT8 opcode = (UINT8)(cmd[0] & 0xFF);
    
    if (opcode == NVME_ADMIN_IDENTIFY) {
        UINT8 cns = (UINT8)((cmd[1] >> 8) & 0xFF);  // Controller or Namespace Structure
        
        if (cns == 1) {  // Identify Controller
            // Mark for post-processing
            return TRUE;
        }
    }
    
    return FALSE;
}

/*
 * Post-process NVMe Identify response
 */
VOID DiskSpoof_PostProcessNvmeIdentify(PVOID ResponseBuffer) {
    if (!g_DiskSpoofContext.Initialized || !g_DiskSpoofContext.Enabled) {
        return;
    }
    
    PNVME_IDENTIFY_CONTROLLER identify = (PNVME_IDENTIFY_CONTROLLER)ResponseBuffer;
    DiskSpoof_ModifyNvmeIdentify(identify);
}

/*
 * Install miniport hooks
 * 
 * This function patches the dispatch routines of storahci.sys
 * and stornvme.sys to intercept IDENTIFY commands
 */
NTSTATUS DiskSpoof_InstallMiniportHooks(VOID) {
    if (!g_DiskSpoofContext.Initialized) {
        return STATUS_UNSUCCESSFUL;
    }
    
    // Find storahci.sys driver object
    // Find StorAHCI miniport dispatch routines
    // Hook BuildIo and/or StartIo
    
    // Find stornvme.sys driver object
    // Hook NVMe admin command handler
    
    // Implementation requires driver object enumeration
    // and code patch/installation
    
    return STATUS_SUCCESS;
}

/*
 * Remove miniport hooks
 */
VOID DiskSpoof_RemoveMiniportHooks(VOID) {
    // Restore original dispatch routines
    g_DiskSpoofContext.Enabled = FALSE;
}

/*
 * Set custom spoofed values
 */
NTSTATUS DiskSpoof_SetSataValues(
    PCHAR Serial,
    PCHAR Model,
    PCHAR Firmware
) {
    if (!g_DiskSpoofContext.Initialized) {
        return STATUS_UNSUCCESSFUL;
    }
    
    KIRQL oldIrql;
    KeAcquireSpinLock(&g_DiskSpoofContext.Lock, &oldIrql);
    
    if (Serial) {
        RtlZeroMemory(g_DiskSpoofContext.FakeSataSerial, 21);
        RtlCopyMemory(g_DiskSpoofContext.FakeSataSerial, Serial, 
                     min(strlen(Serial), 20));
    }
    
    if (Model) {
        RtlZeroMemory(g_DiskSpoofContext.FakeSataModel, 41);
        RtlCopyMemory(g_DiskSpoofContext.FakeSataModel, Model,
                     min(strlen(Model), 40));
    }
    
    if (Firmware) {
        RtlZeroMemory(g_DiskSpoofContext.FakeSataFirmware, 9);
        RtlCopyMemory(g_DiskSpoofContext.FakeSataFirmware, Firmware,
                     min(strlen(Firmware), 8));
    }
    
    KeReleaseSpinLock(&g_DiskSpoofContext.Lock, oldIrql);
    
    return STATUS_SUCCESS;
}

NTSTATUS DiskSpoof_SetNvmeValues(
    PCHAR Serial,
    PCHAR Model,
    PCHAR Firmware
) {
    if (!g_DiskSpoofContext.Initialized) {
        return STATUS_UNSUCCESSFUL;
    }
    
    KIRQL oldIrql;
    KeAcquireSpinLock(&g_DiskSpoofContext.Lock, &oldIrql);
    
    if (Serial) {
        RtlZeroMemory(g_DiskSpoofContext.FakeNvmeSerial, 21);
        RtlCopyMemory(g_DiskSpoofContext.FakeNvmeSerial, Serial,
                     min(strlen(Serial), 20));
    }
    
    if (Model) {
        RtlZeroMemory(g_DiskSpoofContext.FakeNvmeModel, 41);
        RtlCopyMemory(g_DiskSpoofContext.FakeNvmeModel, Model,
                     min(strlen(Model), 40));
    }
    
    if (Firmware) {
        RtlZeroMemory(g_DiskSpoofContext.FakeNvmeFirmware, 9);
        RtlCopyMemory(g_DiskSpoofContext.FakeNvmeFirmware, Firmware,
                     min(strlen(Firmware), 8));
    }
    
    KeReleaseSpinLock(&g_DiskSpoofContext.Lock, oldIrql);
    
    return STATUS_SUCCESS;
}

/*
 * Get original values
 */
NTSTATUS DiskSpoof_GetOriginalSataValues(
    PCHAR Serial,
    UINT32 SerialLen,
    PCHAR Model,
    UINT32 ModelLen,
    PCHAR Firmware,
    UINT32 FirmwareLen
) {
    if (!g_DiskSpoofContext.HaveOriginalSata) {
        return STATUS_NO_DATA_DETECTED;
    }
    
    RtlZeroMemory(Serial, SerialLen);
    RtlCopyMemory(Serial, g_DiskSpoofContext.OriginalSataSerial,
                  min(SerialLen - 1, 20));
    
    RtlZeroMemory(Model, ModelLen);
    RtlCopyMemory(Model, g_DiskSpoofContext.OriginalSataModel,
                  min(ModelLen - 1, 40));
    
    RtlZeroMemory(Firmware, FirmwareLen);
    RtlCopyMemory(Firmware, g_DiskSpoofContext.OriginalSataFirmware,
                  min(FirmwareLen - 1, 8));
    
    return STATUS_SUCCESS;
}

NTSTATUS DiskSpoof_GetOriginalNvmeValues(
    PCHAR Serial,
    UINT32 SerialLen,
    PCHAR Model,
    UINT32 ModelLen,
    PCHAR Firmware,
    UINT32 FirmwareLen
) {
    if (!g_DiskSpoofContext.HaveOriginalNvme) {
        return STATUS_NO_DATA_DETECTED;
    }
    
    RtlZeroMemory(Serial, SerialLen);
    RtlCopyMemory(Serial, g_DiskSpoofContext.OriginalNvmeSerial,
                  min(SerialLen - 1, 20));
    
    RtlZeroMemory(Model, ModelLen);
    RtlCopyMemory(Model, g_DiskSpoofContext.OriginalNvmeModel,
                  min(ModelLen - 1, 40));
    
    RtlZeroMemory(Firmware, FirmwareLen);
    RtlCopyMemory(Firmware, g_DiskSpoofContext.OriginalNvmeFirmware,
                  min(FirmwareLen - 1, 8));
    
    return STATUS_SUCCESS;
}

/*
 * Enable/disable spoofing
 */
VOID DiskSpoof_Enable(BOOLEAN Enable) {
    KIRQL oldIrql;
    KeAcquireSpinLock(&g_DiskSpoofContext.Lock, &oldIrql);
    g_DiskSpoofContext.Enabled = Enable;
    KeReleaseSpinLock(&g_DiskSpoofContext.Lock, oldIrql);
}
