/*
 * Monitor EDID (Extended Display Identification Data) Spoofing
 * 
 * Intercepts I2C/DDC EDID reads to return synthetic display information,
 * randomizing monitor hardware fingerprints.
 */

#include <ntddk.h>

// EDID structure definitions
#define EDID_SIZE               128
#define EDID_EXTENSION_SIZE     128
#define EDID_MAX_EXTENSIONS     255

// EDID header
#define EDID_HEADER             {0x00, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0x00}

// EDID offsets
#define EDID_OFFSET_HEADER          0
#define EDID_OFFSET_MANUFACTURER    8
#define EDID_OFFSET_PRODUCT_CODE    10
#define EDID_OFFSET_SERIAL          12
#define EDID_OFFSET_MANUF_WEEK      16
#define EDID_OFFSET_MANUF_YEAR     17
#define EDID_OFFSET_EDID_VERSION    18
#define EDID_OFFSET_EDID_REVISION   19
#define EDID_OFFSET_INPUT_PARAMS    20
#define EDID_OFFSET_HORIZ_SIZE_CM   21
#define EDID_OFFSET_VERT_SIZE_CM    22
#define EDID_OFFSET_GAMMA          23
#define EDID_OFFSET_FEATURES       24
#define EDID_OFFSET_CHROMA         25
#define EDID_OFFSET_TIMINGS        35
#define EDID_OFFSET_STD_TIMING     38
#define EDID_OFFSET_DESCRIPTOR1    54
#define EDID_OFFSET_DESCRIPTOR2    72
#define EDID_OFFSET_DESCRIPTOR3    90
#define EDID_OFFSET_DESCRIPTOR4    108
#define EDID_OFFSET_EXTENSIONS     126
#define EDID_OFFSET_CHECKSUM       127

// Display descriptor tags
#define DISPLAY_DESCRIPTOR_SERIAL   0xFF
#define DISPLAY_DESCRIPTOR_ASCII    0xFE
#define DISPLAY_DESCRIPTOR_NAME     0xFC
#define DISPLAY_DESCRIPTOR_RANGE    0xFD

// I2C/DDC definitions
#define DDC_I2C_ADDRESS         0x50
#define DDC_SEGMENT_ADDRESS     0x30
#define I2C_CLOCK_RATE          100000

// Context for EDID spoofing
typedef struct _EDID_SPOOF_CONTEXT {
    BOOLEAN         Initialized;
    BOOLEAN         Enabled;
    
    // Fake EDID data
    UINT8           FakeEdid[EDID_SIZE];
    UINT32          FakeEdidSize;
    
    // Original EDID (for restore)
    BOOLEAN         HaveOriginal;
    UINT8           OriginalEdid[EDID_SIZE];
    UINT32          OriginalEdidSize;
    
    // Current display info
    struct {
        CHAR    ManufacturerId[4];
        UINT16  ProductCode;
        UINT32  SerialNumber;
        UINT8   ManufactureWeek;
        UINT8   ManufactureYear;
        CHAR    DisplayName[14];
        CHAR    SerialString[14];
    } CurrentInfo;
    
    KSPIN_LOCK      Lock;
} EDID_SPOOF_CONTEXT;

static EDID_SPOOF_CONTEXT g_EdidContext = {0};

// Common manufacturer IDs (3-letter PNP ID encoded)
#define MANUFACTURER_DELL       0x5C23  // DEL
#define MANUFACTURER_SAMSUNG    0x4CA3  // SAM
#define MANUFACTURER_LG         0xE430  // GSM
#define MANUFACTURER_ASUS       0x060D  // AUS
#define MANUFACTURER_ACER       0x0432  // ACR
#define MANUFACTURER_HP         0x2204  // HWP
#define MANUFACTURER_BENQ       0x09D1  // BNQ
#define MANUFACTURER_VIEWSONIC  0x5A63  // VSC
#define MANUFACTURER_PHILIPS    0xC463  // PHL
#define MANUFACTURER_AOC        0xC430  // AOC

/*
 * Encode 3-letter manufacturer ID to EDID format
 */
UINT16 Edid_EncodeManufacturerId(PCHAR Id) {
    // EDID uses compressed ASCII: 5 bits per letter, A=1, B=2, ...
    // Bits 14-10: First letter
    // Bits 9-5: Second letter
    // Bits 4-0: Third letter
    
    UINT16 result = 0;
    for (INT i = 0; i < 3 && Id[i]; i++) {
        UINT8 letter = (UINT8)((Id[i] - 'A' + 1) & 0x1F);
        result |= (letter << ((2 - i) * 5));
    }
    return result;
}

/*
 * Decode EDID manufacturer ID to string
 */
VOID Edid_DecodeManufacturerId(UINT16 Encoded, PCHAR Result) {
    Result[0] = (CHAR)(((Encoded >> 10) & 0x1F) + 'A' - 1);
    Result[1] = (CHAR)(((Encoded >> 5) & 0x1F) + 'A' - 1);
    Result[2] = (CHAR)((Encoded & 0x1F) + 'A' - 1);
    Result[3] = '\0';
}

/*
 * Calculate EDID checksum
 */
UINT8 Edid_CalculateChecksum(PUINT8 EdidData, UINT32 Size) {
    UINT8 sum = 0;
    for (UINT32 i = 0; i < Size; i++) {
        sum += EdidData[i];
    }
    return (UINT8)(256 - sum);  // Checksum byte makes sum == 0
}

/*
 * Generate a random but valid fake EDID
 */
VOID Edid_GenerateFakeEdid(VOID) {
    RtlZeroMemory(g_EdidContext.FakeEdid, EDID_SIZE);
    
    // Header
    UINT8 header[] = EDID_HEADER;
    RtlCopyMemory(g_EdidContext.FakeEdid, header, 8);
    
    // Random manufacturer
    UINT16 manufacturers[] = {
        MANUFACTURER_DELL, MANUFACTURER_SAMSUNG, MANUFACTURER_LG,
        MANUFACTURER_ASUS, MANUFACTURER_ACER, MANUFACTURER_HP,
        MANUFACTURER_BENQ, MANUFACTURER_VIEWSONIC, MANUFACTURER_PHILIPS
    };
    UINT16 manufId = manufacturers[RtlRandomEx(&g_EdidContext.FakeEdid[0]) % 
                                    (sizeof(manufacturers)/sizeof(manufacturers[0]))];
    
    g_EdidContext.FakeEdid[EDID_OFFSET_MANUFACTURER] = (UINT8)(manufId & 0xFF);
    g_EdidContext.FakeEdid[EDID_OFFSET_MANUFACTURER + 1] = (UINT8)(manufId >> 8);
    Edid_DecodeManufacturerId(manufId, g_EdidContext.CurrentInfo.ManufacturerId);
    
    // Random product code
    UINT16 productCode = (UINT16)(RtlRandomEx(&g_EdidContext.FakeEdid[0]) & 0xFFFF);
    g_EdidContext.FakeEdid[EDID_OFFSET_PRODUCT_CODE] = (UINT8)(productCode & 0xFF);
    g_EdidContext.FakeEdid[EDID_OFFSET_PRODUCT_CODE + 1] = (UINT8)(productCode >> 8);
    g_EdidContext.CurrentInfo.ProductCode = productCode;
    
    // Random serial number
    UINT32 serial = RtlRandomEx(&g_EdidContext.FakeEdid[0]);
    RtlCopyMemory(&g_EdidContext.FakeEdid[EDID_OFFSET_SERIAL], &serial, 4);
    g_EdidContext.CurrentInfo.SerialNumber = serial;
    
    // Manufacture date (current year)
    g_EdidContext.FakeEdid[EDID_OFFSET_MANUF_YEAR] = 24;  // 2024 - 1990
    g_EdidContext.FakeEdid[EDID_OFFSET_MANUF_WEEK] = (UINT8)(RtlRandomEx(&g_EdidContext.FakeEdid[0]) % 52 + 1);
    
    // EDID version 1.3 (common)
    g_EdidContext.FakeEdid[EDID_OFFSET_EDID_VERSION] = 1;
    g_EdidContext.FakeEdid[EDID_OFFSET_EDID_REVISION] = 3;
    
    // Video input parameters (digital)
    g_EdidContext.FakeEdid[EDID_OFFSET_INPUT_PARAMS] = 0x0F;  // Digital, 8-bit
    
    // Screen size (16:9 aspect ratio, ~24 inch)
    g_EdidContext.FakeEdid[EDID_OFFSET_HORIZ_SIZE_CM] = 53;
    g_EdidContext.FakeEdid[EDID_OFFSET_VERT_SIZE_CM] = 30;
    
    // Gamma (2.2)
    g_EdidContext.FakeEdid[EDID_OFFSET_GAMMA] = 120;  // (2.2 - 1.0) * 100 = 120
    
    // Features
    g_EdidContext.FakeEdid[EDID_OFFSET_FEATURES] = 0x06;  // RGB, preferred timing
    
    // Chroma coordinates (sRGB)
    // These define color gamut - use standard sRGB values
    UINT8 chroma[] = {0xB3, 0xA4, 0x52, 0x41, 0x26, 0x0C, 0x45, 0xA7, 0x52, 0x41};
    RtlCopyMemory(&g_EdidContext.FakeEdid[EDID_OFFSET_CHROMA], chroma, 10);
    
    // Established timings (standard resolutions)
    g_EdidContext.FakeEdid[EDID_OFFSET_TIMINGS] = 0x0F;  // 720x400, 640x480, 800x600, 1024x768
    
    // Standard timing identifications (common resolutions)
    // Format: 1 byte aspect ratio/refresh, 1 byte X resolution/8 - 31
    struct {
        UINT8 x;
        UINT8 aspect;
    } stdTimings[8] = {
        {0x2D, 0x1C},  // 1920x1080 @ 60Hz (16:9)
        {0x1C, 0x21},  // 1680x1050 @ 60Hz (16:10)
        {0x15, 0xC0},  // 1366x768 @ 60Hz (16:9)
        {0x00, 0x00},  // Unused
        {0x00, 0x00},  // Unused
        {0x00, 0x00},  // Unused
        {0x00, 0x00},  // Unused
        {0x00, 0x00}   // Unused
    };
    RtlCopyMemory(&g_EdidContext.FakeEdid[EDID_OFFSET_STD_TIMING], stdTimings, 16);
    
    // Descriptor blocks (18 bytes each)
    // Descriptor 1: Preferred timing (1920x1080 @ 60Hz)
    UINT8 preferredTiming[] = {
        0xA6, 0x05,  // Pixel clock (138.5 MHz) = 0x05A6 * 10000
        0x10,        // H active lower 8 bits
        0x08,        // H blank lower 8 bits
        0x78,        // H active/blank upper 4 bits each
        0x38,        // V active lower 8 bits
        0x04,        // V blank lower 8 bits
        0x63,        // V active/blank upper 4 bits each
        0x1A, 0x20,  // H sync offset/width
        0x38, 0x04,  // V sync offset/width
        0x23,        // H/V size upper bits
        0x0F,        // H size lower 8 bits
        0x08,        // V size lower 8 bits
        0x00,        // H/V border
        0x1A,        // Flags (digital, normal display)
        0x00, 0x00   // Padding
    };
    RtlCopyMemory(&g_EdidContext.FakeEdid[EDID_OFFSET_DESCRIPTOR1], preferredTiming, 18);
    
    // Descriptor 2: Display range limits
    UINT8 rangeLimits[] = {
        0x00, 0x00,  // Padding
        0x00,        // Padding
        0xFD,        // Display range descriptor tag
        0x00,        // Padding
        0x32,        // V rate min (50 Hz)
        0x4B,        // V rate max (75 Hz)
        0x1F,        // H rate min (31 kHz)
        0x6E,        // H rate max (110 kHz)
        0x11,        // Max pixel clock (170 MHz / 10)
        0x00,        // No extended timings
        0x0A,        // No padding
        0x20, 0x20,  // Padding
        0x20, 0x20,
        0x20, 0x20,
        0x20, 0x20
    };
    RtlCopyMemory(&g_EdidContext.FakeEdid[EDID_OFFSET_DESCRIPTOR2], rangeLimits, 18);
    
    // Descriptor 3: Display name
    UINT8 displayName[] = {
        0x00, 0x00, 0x00, 0xFC,  // Display name descriptor tag
        0x00,
        'H', 'W', 'I', 'D', 'S', 'p', 'o', 'o', 'f', 'e', 'r',
        0x0A,  // Newline
        0x20, 0x20  // Padding
    };
    RtlCopyMemory(&g_EdidContext.FakeEdid[EDID_OFFSET_DESCRIPTOR3], displayName, 18);
    RtlCopyMemory(g_EdidContext.CurrentInfo.DisplayName, &displayName[5], 13);
    
    // Descriptor 4: Serial number
    UINT8 serialNumber[] = {
        0x00, 0x00, 0x00, 0xFF,  // Serial number descriptor tag
        0x00,
        'S', 'N', '0', '0', '1', '2', '3', '4', '5', '6', '7',
        0x0A,
        0x20, 0x20
    };
    RtlCopyMemory(&g_EdidContext.FakeEdid[EDID_OFFSET_DESCRIPTOR4], serialNumber, 18);
    RtlCopyMemory(g_EdidContext.CurrentInfo.SerialString, &serialNumber[5], 13);
    
    // No extensions
    g_EdidContext.FakeEdid[EDID_OFFSET_EXTENSIONS] = 0;
    
    // Calculate and write checksum
    g_EdidContext.FakeEdid[EDID_OFFSET_CHECKSUM] = 
        Edid_CalculateChecksum(g_EdidContext.FakeEdid, EDID_SIZE - 1);
    
    g_EdidContext.FakeEdidSize = EDID_SIZE;
}

/*
 * Initialize EDID spoofing
 */
NTSTATUS EdidSpoof_Initialize(VOID) {
    RtlZeroMemory(&g_EdidContext, sizeof(g_EdidContext));
    KeInitializeSpinLock(&g_EdidContext.Lock);
    
    Edid_GenerateFakeEdid();
    
    g_EdidContext.Initialized = TRUE;
    g_EdidContext.Enabled = TRUE;
    
    return STATUS_SUCCESS;
}

/*
 * Hook for EDID read (I2C/DDC)
 * 
 * This function is called when the display miniport reads EDID
 * via I2C. We return our fake EDID instead.
 */
NTSTATUS EdidSpoof_HookEdidRead(
    PVOID I2CContext,
    UINT8 Segment,
    UINT8 Offset,
    PUINT8 Buffer,
    UINT32 Size
) {
    if (!g_EdidContext.Initialized || !g_EdidContext.Enabled) {
        return STATUS_UNSUCCESSFUL;  // Pass through to real hardware
    }
    
    KIRQL oldIrql;
    KeAcquireSpinLock(&g_EdidContext.Lock, &oldIrql);
    
    // Save original EDID if this is the first read
    if (!g_EdidContext.HaveOriginal && Size >= EDID_SIZE) {
        RtlCopyMemory(g_EdidContext.OriginalEdid, Buffer, min(Size, EDID_SIZE));
        g_EdidContext.OriginalEdidSize = Size;
        g_EdidContext.HaveOriginal = TRUE;
    }
    
    // Return fake EDID
    UINT32 copySize = min(Size, g_EdidContext.FakeEdidSize);
    RtlCopyMemory(Buffer, g_EdidContext.FakeEdid, copySize);
    
    KeReleaseSpinLock(&g_EdidContext.Lock, oldIrql);
    
    return STATUS_SUCCESS;
}

/*
 * Enable/disable EDID spoofing
 */
VOID EdidSpoof_Enable(BOOLEAN Enable) {
    KIRQL oldIrql;
    KeAcquireSpinLock(&g_EdidContext.Lock, &oldIrql);
    g_EdidContext.Enabled = Enable;
    KeReleaseSpinLock(&g_EdidContext.Lock, oldIrql);
}

/*
 * Set custom EDID data
 */
NTSTATUS EdidSpoof_SetCustomEdid(PUINT8 EdidData, UINT32 Size) {
    if (!g_EdidContext.Initialized) {
        return STATUS_UNSUCCESSFUL;
    }
    
    if (Size > EDID_SIZE) {
        return STATUS_INVALID_PARAMETER;
    }
    
    KIRQL oldIrql;
    KeAcquireSpinLock(&g_EdidContext.Lock, &oldIrql);
    
    RtlCopyMemory(g_EdidContext.FakeEdid, EdidData, Size);
    
    // Recalculate checksum if size is full EDID
    if (Size == EDID_SIZE) {
        g_EdidContext.FakeEdid[EDID_OFFSET_CHECKSUM] = 
            Edid_CalculateChecksum(g_EdidContext.FakeEdid, EDID_SIZE - 1);
    }
    
    g_EdidContext.FakeEdidSize = Size;
    KeReleaseSpinLock(&g_EdidContext.Lock, oldIrql);
    
    return STATUS_SUCCESS;
}

/*
 * Get current fake EDID info
 */
VOID EdidSpoof_GetCurrentInfo(
    PCHAR ManufacturerId,
    PUINT16 ProductCode,
    PUINT32 SerialNumber,
    PCHAR DisplayName,
    UINT32 DisplayNameSize
) {
    KIRQL oldIrql;
    KeAcquireSpinLock(&g_EdidContext.Lock, &oldIrql);
    
    if (ManufacturerId) {
        RtlCopyMemory(ManufacturerId, g_EdidContext.CurrentInfo.ManufacturerId, 4);
    }
    if (ProductCode) {
        *ProductCode = g_EdidContext.CurrentInfo.ProductCode;
    }
    if (SerialNumber) {
        *SerialNumber = g_EdidContext.CurrentInfo.SerialNumber;
    }
    if (DisplayName && DisplayNameSize > 0) {
        RtlCopyMemory(DisplayName, g_EdidContext.CurrentInfo.DisplayName,
                      min(DisplayNameSize - 1, 14));
        DisplayName[min(DisplayNameSize - 1, 14)] = '\0';
    }
    
    KeReleaseSpinLock(&g_EdidContext.Lock, oldIrql);
}

/*
 * Install EDID hooks into display miniport
 */
NTSTATUS EdidSpoof_InstallHooks(VOID) {
    // Find display miniport drivers (e.g., iagp.sys, atikmdag.sys, nvlddmkm.sys)
    // Hook their I2C/DDC read functions
    // This is vendor-specific
    
    return STATUS_SUCCESS;
}

/*
 * Generate new random EDID
 */
VOID EdidSpoof_Randomize(VOID) {
    KIRQL oldIrql;
    KeAcquireSpinLock(&g_EdidContext.Lock, &oldIrql);
    Edid_GenerateFakeEdid();
    KeReleaseSpinLock(&g_EdidContext.Lock, oldIrql);
}
