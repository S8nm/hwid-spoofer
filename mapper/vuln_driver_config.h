/*
 * Vulnerable Driver Configuration Framework
 * Supports multiple vulnerable drivers for driver-agnostic mapping
 */

#ifndef VULN_DRIVER_CONFIG_H
#define VULN_DRIVER_CONFIG_H

#include <windows.h>

#ifdef __cplusplus
extern "C" {
#endif

// Driver type identifiers
typedef enum _VULN_DRIVER_TYPE {
    VULN_DRIVER_INTEL_NAL = 0,      // iqvw64e.sys (Intel NAL)
    VULN_DRIVER_GIGABYTE_GDRV,       // gdrv.sys (Gigabyte vulnerable driver)
    VULN_DRIVER_ASROCK_RGB,          // AsrDrv10x64.sys (ASRock RGB)
    VULN_DRIVER_PROCESS_HACKER,      // sz-ks64.sys (Process Hacker driver)
    VULN_DRIVER_DELL_BIOS,          // Dell BIOS driver
    VULN_DRIVER_GLAZIO,             // GLAZIO.sys (Intel Overclocking)
    VULN_DRIVER_COUNT
} VULN_DRIVER_TYPE;

// IOCTL buffer types
typedef enum _IOCTL_BUFFER_TYPE {
    IOCTL_BUFFER_MAP_IO_SPACE = 0,
    IOCTL_BUFFER_COPY_MEMORY,
    IOCTL_BUFFER_UNMAP_IO_SPACE,
    IOCTL_BUFFER_ALLOCATE_POOL,
    IOCTL_BUFFER_COUNT
} IOCTL_BUFFER_TYPE;

// Vulnerable driver configuration structure
typedef struct _VULN_DRIVER_CONFIG {
    // Identification
    VULN_DRIVER_TYPE Type;
    const char* Name;
    const char* DeviceName;          // e.g., "\\\\.\\Nal"
    const char* ServiceNamePrefix;   // e.g., "nal" (randomized)
    const char* DriverFileName;      // e.g., "iqvw64e.sys"
    
    // IOCTL codes
    DWORD IoctlCode;
    
    // Function case numbers for driver dispatch
    // These map to the driver's internal switch cases
    ULONG64 CaseMapPhysical;         // Map physical memory
    ULONG64 CaseUnmapPhysical;       // Unmap physical memory
    ULONG64 CaseCopyMemory;          // Copy memory (read/write)
    ULONG64 CaseAllocatePool;        // Allocate kernel pool (if supported)
    ULONG64 CaseGetPhysAddr;         // Get physical address (if supported)
    ULONG64 CaseMapIoSpace;          // Map I/O space (if supported)
    
    // Buffer layouts and sizes
    SIZE_T BufferSizeMap;
    SIZE_T BufferSizeCopy;
    SIZE_T BufferSizeUnmap;
    SIZE_T BufferSizeAlloc;
    
    // Feature flags
    BOOL UsesMdlMapping;             // Uses MDL for memory mapping
    BOOL RequiresPhysicalContiguous; // Requires physically contiguous memory
    BOOL SupportsKernelWrite;        // Can write to kernel memory directly
    BOOL SupportsPoolAllocation;     // Supports ExAllocatePool equivalent
    BOOL SupportsPhysicalTranslation; // Supports VA->PA translation
    
    // Security constraints
    ULONG MaxMappingSize;            // Maximum bytes that can be mapped
    ULONG AlignmentRequirement;      // Memory alignment requirement (0=none)
    
    // Required privileges/conditions
    BOOL RequiresSecureBootDisabled; // Requires Secure Boot to be off
    BOOL RequiresTestMode;           // Requires Windows Test Mode
    BOOL RequiresDebugMode;          // Requires kernel debugging enabled
    
    // Version/compatibility
    ULONG MinBuildNumber;            // Minimum Windows build (0=any)
    ULONG MaxBuildNumber;            // Maximum Windows build (0=any)
    
    // Detection/blocklist status (runtime filled)
    BOOL IsBlocklisted;              // Is this driver on MS blocklist?
    BOOL WasTested;                  // Has this driver been tested this run?
    BOOL CanLoad;                    // Did the driver successfully load?
} VULN_DRIVER_CONFIG;

// Predefined configurations for known vulnerable drivers
extern VULN_DRIVER_CONFIG g_VulnDriverConfigs[VULN_DRIVER_COUNT];

// Function prototypes
VULN_DRIVER_CONFIG* GetDriverConfig(VULN_DRIVER_TYPE type);
const char* GetDriverTypeName(VULN_DRIVER_TYPE type);
BOOL IsDriverCompatible(VULN_DRIVER_CONFIG* config, ULONG currentBuild);
BOOL IsDriverAvailable(VULN_DRIVER_CONFIG* config);

// Specific driver configurations
VULN_DRIVER_CONFIG* GetIntelNalConfig(void);
VULN_DRIVER_CONFIG* GetGigabyteGdrvConfig(void);
VULN_DRIVER_CONFIG* GetAsrockRgbConfig(void);
VULN_DRIVER_CONFIG* GetProcessHackerConfig(void);
VULN_DRIVER_CONFIG* GetDellBiosConfig(void);
VULN_DRIVER_CONFIG* GetGlazioConfig(void);

#ifdef __cplusplus
}
#endif

#endif // VULN_DRIVER_CONFIG_H
