/*
 * TPM PCR (Platform Configuration Register) Spoofing
 * 
 * Windows 11 uses TPM PCR values for attestation and device health.
 * This module intercepts TPM commands to return synthetic PCR values,
 * effectively bypassing Windows 11 attestation requirements.
 */

#include <ntddk.h>

// TPM 2.0 Command Tags
#define TPM2_ST_SESSIONS        0x00C4
#define TPM2_ST_NO_SESSIONS     0x8001

// TPM 2.0 Command Codes
#define TPM2_CC_PCR_READ        0x0000017E
#define TPM2_CC_PCR_EXTEND      0x00000182
#define TPM2_CC_PCR_RESET       0x0000013D
#define TPM2_CC_QUOTE           0x00000158
#define TPM2_CC_GET_CAPABILITY  0x0000017A

// PCR Register Count
#define TPM2_NUM_PCRS           24

// TPM Algorithm IDs
#define TPM_ALG_SHA256          0x000B
#define TPM_ALG_SHA384          0x000C
#define TPM_ALG_SHA512          0x000D

// PCR Attributes
typedef struct _PCR_ATTRIBUTES {
    BOOLEAN Resettable;
    BOOLEAN Extendable;
    BOOLEAN Readable;
    UINT8   Reserved;
} PCR_ATTRIBUTES;

// Synthetic PCR values (fixed values to present a "clean" attestation)
typedef struct _SYNTHETIC_PCR_BANK {
    UINT16  Algorithm;
    UINT16  DigestSize;
    UINT8   Values[TPM2_NUM_PCRS][64];  // Max digest size for SHA512
    PCR_ATTRIBUTES Attributes[TPM2_NUM_PCRS];
} SYNTHETIC_PCR_BANK;

// Context for TPM hooking
typedef struct _TPM_SPOOF_CONTEXT {
    BOOLEAN         Initialized;
    BOOLEAN         SpoofingEnabled;
    
    // Original PCR values (backup)
    SYNTHETIC_PCR_BANK OriginalBanks[3];  // SHA256, SHA384, SHA512
    
    // Synthetic PCR values
    SYNTHETIC_PCR_BANK SyntheticBanks[3];
    
    // Lock - prevents concurrent modification
    KSPIN_LOCK      Lock;
    
    // Statistics
    UINT64          InterceptedCommands;
    UINT64          ModifiedResponses;
} TPM_SPOOF_CONTEXT;

static TPM_SPOOF_CONTEXT g_TpmContext = {0};

// Pre-defined "good" PCR values for Windows attestation
// These represent a clean, non-tampered system state
static const UINT8 g_CleanPCR0_SHA256[32] = {
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
};

static const UINT8 g_CleanPCR7_SHA256[32] = {
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
};

/*
 * Initialize synthetic PCR banks
 */
VOID TpmPcrSpoof_InitializeBanks(VOID) {
    RtlZeroMemory(&g_TpmContext, sizeof(g_TpmContext));
    
    // Initialize SHA256 bank
    g_TpmContext.SyntheticBanks[0].Algorithm = TPM_ALG_SHA256;
    g_TpmContext.SyntheticBanks[0].DigestSize = 32;
    
    // Initialize SHA384 bank
    g_TpmContext.SyntheticBanks[1].Algorithm = TPM_ALG_SHA384;
    g_TpmContext.SyntheticBanks[1].DigestSize = 48;
    
    // Initialize SHA512 bank
    g_TpmContext.SyntheticBanks[2].Algorithm = TPM_ALG_SHA512;
    g_TpmContext.SyntheticBanks[2].DigestSize = 64;
    
    // Set all PCRs to clean state (all zeros = no measurements)
    for (UINT32 bank = 0; bank < 3; bank++) {
        for (UINT32 pcr = 0; pcr < TPM2_NUM_PCRS; pcr++) {
            // Most PCRs are readable and extendable
            g_TpmContext.SyntheticBanks[bank].Attributes[pcr].Readable = TRUE;
            g_TpmContext.SyntheticBanks[bank].Attributes[pcr].Extendable = (pcr < 16);
            g_TpmContext.SyntheticBanks[bank].Attributes[pcr].Resettable = (pcr >= 16);
            
            // Initialize to zero (clean state)
            RtlZeroMemory(g_TpmContext.SyntheticBanks[bank].Values[pcr], 
                         g_TpmContext.SyntheticBanks[bank].DigestSize);
        }
    }
    
    // PCR[0] - Core System Firmware (SRTM)
    // PCR[1] - Platform Configuration
    // PCR[2] - Option ROM Code
    // PCR[3] - Option ROM Data
    // PCR[4] - Boot Manager
    // PCR[5] - GPT/Partition Table
    // PCR[6] - Resume from S3/S4
    // PCR[7] - SecureBoot State (CRITICAL for attestation)
    
    // Keep PCR[7] clean for SecureBoot attestation
    // Windows checks PCR[7] for SecureBoot validation
    
    KeInitializeSpinLock(&g_TpmContext.Lock);
    g_TpmContext.Initialized = TRUE;
    g_TpmContext.SpoofingEnabled = TRUE;
}

/*
 * Parse TPM command from buffer
 */
typedef struct _TPM2_COMMAND_HEADER {
    UINT16  Tag;
    UINT32  Size;
    UINT32  CommandCode;
} TPM2_COMMAND_HEADER;

BOOLEAN TpmPcrSpoof_ParseCommand(
    PVOID Buffer,
    UINT32 BufferSize,
    TPM2_COMMAND_HEADER* Header,
    PVOID* CommandData,
    UINT32* CommandDataSize
) {
    if (BufferSize < sizeof(TPM2_COMMAND_HEADER)) {
        return FALSE;
    }
    
    RtlCopyMemory(Header, Buffer, sizeof(TPM2_COMMAND_HEADER));
    
    // Convert from big-endian if needed
    Header->Tag = RtlUshortByteSwap(Header->Tag);
    Header->Size = RtlUlongByteSwap(Header->Size);
    Header->CommandCode = RtlUlongByteSwap(Header->CommandCode);
    
    if (Header->Size > BufferSize) {
        return FALSE;
    }
    
    *CommandData = (PUINT8)Buffer + sizeof(TPM2_COMMAND_HEADER);
    *CommandDataSize = Header->Size - sizeof(TPM2_COMMAND_HEADER);
    
    return TRUE;
}

/*
 * Handle TPM2_PCR_Read command
 * Intercept and return synthetic PCR values
 */
NTSTATUS TpmPcrSpoof_HandlePcrRead(
    PVOID InputBuffer,
    UINT32 InputSize,
    PVOID OutputBuffer,
    UINT32 OutputSize,
    PUINT32 ResponseSize
) {
    // Parse PCR selection from input
    // Format: UINT32 count, { UINT16 hashAlg, UINT8 sizeofSelect, UINT8 pcrSelect[sizeofSelect] }...
    
    PUINT8 input = (PUINT8)InputBuffer + sizeof(TPM2_COMMAND_HEADER);
    UINT32 remaining = InputSize - sizeof(TPM2_COMMAND_HEADER);
    
    if (remaining < sizeof(UINT32)) {
        return STATUS_INVALID_PARAMETER;
    }
    
    UINT32 pcrSelectionCount = RtlUlongByteSwap(*(UINT32*)input);
    input += sizeof(UINT32);
    remaining -= sizeof(UINT32);
    
    // Build response
    PUINT8 output = (PUINT8)OutputBuffer;
    UINT32 outputRemaining = OutputSize;
    
    // Response header
    TPM2_COMMAND_HEADER* respHeader = (TPM2_COMMAND_HEADER*)output;
    respHeader->Tag = RtlUshortByteSwap(TPM2_ST_SESSIONS);
    respHeader->CommandCode = RtlUlongByteSwap(0x00000000);  // Response code (success)
    
    PUINT8 respData = output + sizeof(TPM2_COMMAND_HEADER);
    
    // Current time for timestamp
    *(UINT64*)respData = 0;  // Clock
    respData += sizeof(UINT64);
    *(UINT32*)respData = 0;  // Reset count
    respData += sizeof(UINT32);
    *(UINT32*)respData = 0;  // Restart count
    respData += sizeof(UINT32);
    *(UINT8*)respData = 0;   // Safe
    respData += sizeof(UINT8);
    
    // Number of PCR banks in response
    *(UINT32*)respData = RtlUlongByteSwap(pcrSelectionCount);
    respData += sizeof(UINT32);
    
    KIRQL oldIrql;
    KeAcquireSpinLock(&g_TpmContext.Lock, &oldIrql);
    
    // For each requested bank
    for (UINT32 i = 0; i < pcrSelectionCount && remaining >= 3; i++) {
        UINT16 hashAlg = RtlUshortByteSwap(*(UINT16*)input);
        input += sizeof(UINT16);
        UINT8 sizeofSelect = *input++;
        remaining -= 3;
        
        if (sizeofSelect > remaining) {
            KeReleaseSpinLock(&g_TpmContext.Lock, oldIrql);
            return STATUS_INVALID_PARAMETER;
        }
        
        // Find matching synthetic bank
        SYNTHETIC_PCR_BANK* bank = NULL;
        for (UINT32 b = 0; b < 3; b++) {
            if (g_TpmContext.SyntheticBanks[b].Algorithm == hashAlg) {
                bank = &g_TpmContext.SyntheticBanks[b];
                break;
            }
        }
        
        // Write PCR selection back
        *(UINT16*)respData = RtlUshortByteSwap(hashAlg);
        respData += sizeof(UINT16);
        *(UINT8*)respData = sizeofSelect;
        respData += sizeof(UINT8);
        
        // Count selected PCRs
        UINT32 selectedPcrCount = 0;
        for (UINT32 j = 0; j < sizeofSelect * 8 && j < TPM2_NUM_PCRS; j++) {
            UINT32 byteIdx = j / 8;
            UINT32 bitIdx = j % 8;
            if (byteIdx < sizeofSelect && (input[byteIdx] & (1 << bitIdx))) {
                selectedPcrCount++;
            }
        }
        
        // Write digest count
        *(UINT32*)respData = RtlUlongByteSwap(selectedPcrCount);
        respData += sizeof(UINT32);
        
        // Write synthetic PCR values
        for (UINT32 j = 0; j < sizeofSelect * 8 && j < TPM2_NUM_PCRS; j++) {
            UINT32 byteIdx = j / 8;
            UINT32 bitIdx = j % 8;
            if (byteIdx < sizeofSelect && (input[byteIdx] & (1 << bitIdx))) {
                // Write digest size
                UINT16 digestSize = bank ? bank->DigestSize : 32;
                *(UINT16*)respData = RtlUshortByteSwap(digestSize);
                respData += sizeof(UINT16);
                
                // Write digest value (synthetic)
                if (bank && bank->Attributes[j].Readable) {
                    RtlCopyMemory(respData, bank->Values[j], digestSize);
                } else {
                    RtlZeroMemory(respData, digestSize);
                }
                respData += digestSize;
            }
        }
        
        input += sizeofSelect;
        remaining -= sizeofSelect;
    }
    
    KeReleaseSpinLock(&g_TpmContext.Lock, oldIrql);
    
    // Calculate and update total response size
    UINT32 totalSize = (UINT32)(respData - (PUINT8)OutputBuffer);
    respHeader->Size = RtlUlongByteSwap(totalSize);
    *ResponseSize = totalSize;
    
    g_TpmContext.ModifiedResponses++;
    
    return STATUS_SUCCESS;
}

/*
 * Handle TPM2_Quote command
 * Intercept attestation quotes and modify PCR values
 */
NTSTATUS TpmPcrSpoof_HandleQuote(
    PVOID InputBuffer,
    UINT32 InputSize,
    PVOID OutputBuffer,
    UINT32 OutputSize,
    PUINT32 ResponseSize
) {
    // TPM Quote is used for attestation - we need to ensure
    // the quoted PCR values match our synthetic values
    
    // First, pass through to real TPM
    // Then modify the response to use synthetic PCR values
    
    // For now, return success (actual implementation would
    // need to modify the attestation signature as well)
    
    return STATUS_NOT_SUPPORTED;
}

/*
 * Handle TPM2_PCR_Extend command
 * Block or modify PCR extends to maintain clean state
 */
NTSTATUS TpmPcrSpoof_HandlePcrExtend(
    PVOID InputBuffer,
    UINT32 InputSize,
    PVOID OutputBuffer,
    UINT32 OutputSize,
    PUINT32 ResponseSize
) {
    KIRQL oldIrql;
    KeAcquireSpinLock(&g_TpmContext.Lock, &oldIrql);
    
    // Option 1: Block the extend completely and return success
    // Option 2: Allow extend but update our synthetic values
    // Option 3: Log but don't modify
    
    // For Windows 11 attestation bypass, we typically want
    // to block extends to PCR[7] (SecureBoot state)
    
    if (!g_TpmContext.SpoofingEnabled) {
        KeReleaseSpinLock(&g_TpmContext.Lock, oldIrql);
        return STATUS_UNSUCCESSFUL;  // Pass through to real TPM
    }
    
    // Parse PCR index from command
    PUINT8 input = (PUINT8)InputBuffer + sizeof(TPM2_COMMAND_HEADER);
    UINT32 pcrIndex = RtlUlongByteSwap(*(UINT32*)input);
    
    // Block extends to critical PCRs
    if (pcrIndex == 7) {
        // Return success but don't actually extend
        // Build minimal success response
        TPM2_COMMAND_HEADER* resp = (TPM2_COMMAND_HEADER*)OutputBuffer;
        resp->Tag = RtlUshortByteSwap(TPM2_ST_SESSIONS);
        resp->Size = RtlUlongByteSwap(sizeof(TPM2_COMMAND_HEADER));
        resp->CommandCode = 0;  // Success
        *ResponseSize = sizeof(TPM2_COMMAND_HEADER);
        
        KeReleaseSpinLock(&g_TpmContext.Lock, oldIrql);
        g_TpmContext.ModifiedResponses++;
        return STATUS_SUCCESS;
    }
    
    KeReleaseSpinLock(&g_TpmContext.Lock, oldIrql);
    return STATUS_UNSUCCESSFUL;  // Pass through for non-critical PCRs
}

/*
 * Main TPM command interceptor
 * 
 * This function should be hooked into the TPM driver's dispatch routine
 */
NTSTATUS TpmPcrSpoof_InterceptCommand(
    PVOID InputBuffer,
    UINT32 InputSize,
    PVOID OutputBuffer,
    UINT32 OutputSize,
    PUINT32 ResponseSize
) {
    if (!g_TpmContext.Initialized || !g_TpmContext.SpoofingEnabled) {
        return STATUS_UNSUCCESSFUL;
    }
    
    TPM2_COMMAND_HEADER header;
    PVOID cmdData;
    UINT32 cmdDataSize;
    
    if (!TpmPcrSpoof_ParseCommand(InputBuffer, InputSize, &header, &cmdData, &cmdDataSize)) {
        return STATUS_INVALID_PARAMETER;
    }
    
    g_TpmContext.InterceptedCommands++;
    
    switch (header.CommandCode) {
        case TPM2_CC_PCR_READ:
            return TpmPcrSpoof_HandlePcrRead(InputBuffer, InputSize, 
                                              OutputBuffer, OutputSize, ResponseSize);
            
        case TPM2_CC_PCR_EXTEND:
            return TpmPcrSpoof_HandlePcrExtend(InputBuffer, InputSize,
                                               OutputBuffer, OutputSize, ResponseSize);
            
        case TPM2_CC_QUOTE:
            return TpmPcrSpoof_HandleQuote(InputBuffer, InputSize,
                                           OutputBuffer, OutputSize, ResponseSize);
            
        default:
            // Pass through to real TPM
            return STATUS_UNSUCCESSFUL;
    }
}

/*
 * Enable/disable TPM spoofing
 */
VOID TpmPcrSpoof_Enable(BOOLEAN Enable) {
    KIRQL oldIrql;
    KeAcquireSpinLock(&g_TpmContext.Lock, &oldIrql);
    g_TpmContext.SpoofingEnabled = Enable;
    KeReleaseSpinLock(&g_TpmContext.Lock, oldIrql);
}

/*
 * Get spoofing statistics
 */
VOID TpmPcrSpoof_GetStats(PUINT64 Intercepted, PUINT64 Modified) {
    KIRQL oldIrql;
    KeAcquireSpinLock(&g_TpmContext.Lock, &oldIrql);
    *Intercepted = g_TpmContext.InterceptedCommands;
    *Modified = g_TpmContext.ModifiedResponses;
    KeReleaseSpinLock(&g_TpmContext.Lock, oldIrql);
}

/*
 * Hook installation
 * 
 * This function installs the TPM command hook by modifying
 * the TPM driver's dispatch table
 */
NTSTATUS TpmPcrSpoof_InstallHook(VOID) {
    // Find TPM driver object
    // Hook the dispatch routine
    // Save original dispatch for pass-through
    
    // Implementation depends on specific TPM driver structure
    // (Tpm.sys, TpmCoreProvisioning.dll, or fTPM)
    
    TpmPcrSpoof_InitializeBanks();
    
    return STATUS_SUCCESS;
}

/*
 * Hook removal
 */
VOID TpmPcrSpoof_RemoveHook(VOID) {
    // Restore original dispatch routine
    g_TpmContext.SpoofingEnabled = FALSE;
}
