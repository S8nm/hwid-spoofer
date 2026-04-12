/*
 * Vulnerable Driver Configurations - Predefined configs for known vulnerable drivers
 */

#include "vuln_driver_config.h"
#include <string.h>

// Intel NAL (iqvw64e.sys) - Original driver used by this spoofer
// IOCTL 0x80862007 with case-based dispatch
static VULN_DRIVER_CONFIG g_IntelNalConfig = {
    .Type = VULN_DRIVER_INTEL_NAL,
    .Name = "Intel NAL (iqvw64e.sys)",
    .DeviceName = "\\\\.\\Nal",
    .ServiceNamePrefix = "nal",
    .DriverFileName = "iqvw64e.sys",
    
    .IoctlCode = 0x80862007,
    
    // Intel NAL case numbers
    .CaseMapPhysical = 0x19,        // MapIoSpace
    .CaseUnmapPhysical = 0x1A,      // UnmapIoSpace
    .CaseCopyMemory = 0x33,         // CopyMemory (read/write)
    .CaseAllocatePool = 0x25,     // AllocatePool
    .CaseGetPhysAddr = 0x26,        // GetPhysicalAddress
    .CaseMapIoSpace = 0x19,         // Same as MapPhysical
    
    // Buffer sizes for Intel NAL
    .BufferSizeMap = 0x30,
    .BufferSizeCopy = 0x30,
    .BufferSizeUnmap = 0x30,
    .BufferSizeAlloc = 0x30,
    
    // Capabilities
    .UsesMdlMapping = TRUE,
    .RequiresPhysicalContiguous = FALSE,
    .SupportsKernelWrite = TRUE,
    .SupportsPoolAllocation = TRUE,
    .SupportsPhysicalTranslation = TRUE,
    
    // Constraints
    .MaxMappingSize = 0x10000000,   // 256MB max
    .AlignmentRequirement = 0x1000, // 4KB alignment
    
    // Requirements
    .RequiresSecureBootDisabled = FALSE,
    .RequiresTestMode = FALSE,
    .RequiresDebugMode = FALSE,
    
    // Compatibility
    .MinBuildNumber = 7600,         // Windows 7
    .MaxBuildNumber = 26000,        // Future Windows builds
    
    // Runtime status (initialized to FALSE)
    .IsBlocklisted = FALSE,
    .WasTested = FALSE,
    .CanLoad = FALSE
};

// Gigabyte GDRV (gdrv.sys) - Alternative vulnerable driver
// Uses physical memory read/write via IOCTLs
static VULN_DRIVER_CONFIG g_GigabyteGdrvConfig = {
    .Type = VULN_DRIVER_GIGABYTE_GDRV,
    .Name = "Gigabyte GDRV (gdrv.sys)",
    .DeviceName = "\\\\.\\GDRV",
    .ServiceNamePrefix = "gdrv",
    .DriverFileName = "gdrv.sys",
    
    .IoctlCode = 0xC3502800,        // Custom IOCTL for GDRV
    
    // GDRV uses direct IOCTL numbers, not cases
    .CaseMapPhysical = 0,
    .CaseUnmapPhysical = 0,
    .CaseCopyMemory = 0xC3502804,   // Physical memory read/write
    .CaseAllocatePool = 0,          // Not supported
    .CaseGetPhysAddr = 0,           // Not supported
    .CaseMapIoSpace = 0,
    
    .BufferSizeMap = 0,
    .BufferSizeCopy = 0x28,
    .BufferSizeUnmap = 0,
    .BufferSizeAlloc = 0,
    
    .UsesMdlMapping = FALSE,
    .RequiresPhysicalContiguous = TRUE,
    .SupportsKernelWrite = TRUE,
    .SupportsPoolAllocation = FALSE,
    .SupportsPhysicalTranslation = FALSE,
    
    .MaxMappingSize = 0x100000000,  // 4GB
    .AlignmentRequirement = 0x1000,
    
    .RequiresSecureBootDisabled = TRUE,
    .RequiresTestMode = FALSE,
    .RequiresDebugMode = FALSE,
    
    .MinBuildNumber = 7600,
    .MaxBuildNumber = 22000,        // Blocked on newer Windows
    
    .IsBlocklisted = TRUE,          // Known to be blocklisted
    .WasTested = FALSE,
    .CanLoad = FALSE
};

// ASRock RGB (AsrDrv10x64.sys) - RGB controller with memory access
static VULN_DRIVER_CONFIG g_AsrockRgbConfig = {
    .Type = VULN_DRIVER_ASROCK_RGB,
    .Name = "ASRock RGB (AsrDrv10x64.sys)",
    .DeviceName = "\\\\.\\AsrDrv10",
    .ServiceNamePrefix = "asrrgb",
    .DriverFileName = "AsrDrv10x64.sys",
    
    .IoctlCode = 0x80002000,
    
    .CaseMapPhysical = 0x80002004,  // Map physical memory
    .CaseUnmapPhysical = 0x80002008, // Unmap
    .CaseCopyMemory = 0x8000200C,     // Read/Write physical
    .CaseAllocatePool = 0x80002010, // Allocate
    .CaseGetPhysAddr = 0,             // Not directly supported
    .CaseMapIoSpace = 0x80002004,
    
    .BufferSizeMap = 0x28,
    .BufferSizeCopy = 0x30,
    .BufferSizeUnmap = 0x20,
    .BufferSizeAlloc = 0x28,
    
    .UsesMdlMapping = TRUE,
    .RequiresPhysicalContiguous = FALSE,
    .SupportsKernelWrite = TRUE,
    .SupportsPoolAllocation = TRUE,
    .SupportsPhysicalTranslation = FALSE,
    
    .MaxMappingSize = 0x8000000,     // 128MB
    .AlignmentRequirement = 0x1000,
    
    .RequiresSecureBootDisabled = FALSE,
    .RequiresTestMode = FALSE,
    .RequiresDebugMode = FALSE,
    
    .MinBuildNumber = 10240,         // Windows 10
    .MaxBuildNumber = 26000,
    
    .IsBlocklisted = FALSE,
    .WasTested = FALSE,
    .CanLoad = FALSE
};

// Process Hacker (sz-ks64.sys) - Signed driver with vulnerability
static VULN_DRIVER_CONFIG g_ProcessHackerConfig = {
    .Type = VULN_DRIVER_PROCESS_HACKER,
    .Name = "Process Hacker (sz-ks64.sys)",
    .DeviceName = "\\\\.\\sz-ks64",
    .ServiceNamePrefix = "szks",
    .DriverFileName = "sz-ks64.sys",
    
    .IoctlCode = 0x80002018,
    
    .CaseMapPhysical = 0x8000201C,
    .CaseUnmapPhysical = 0x80002020,
    .CaseCopyMemory = 0x80002024,
    .CaseAllocatePool = 0x80002028,
    .CaseGetPhysAddr = 0x8000202C,
    .CaseMapIoSpace = 0x8000201C,
    
    .BufferSizeMap = 0x30,
    .BufferSizeCopy = 0x30,
    .BufferSizeUnmap = 0x28,
    .BufferSizeAlloc = 0x28,
    
    .UsesMdlMapping = TRUE,
    .RequiresPhysicalContiguous = FALSE,
    .SupportsKernelWrite = TRUE,
    .SupportsPoolAllocation = TRUE,
    .SupportsPhysicalTranslation = TRUE,
    
    .MaxMappingSize = 0x40000000,    // 1GB
    .AlignmentRequirement = 0x1000,
    
    .RequiresSecureBootDisabled = FALSE,
    .RequiresTestMode = FALSE,
    .RequiresDebugMode = FALSE,
    
    .MinBuildNumber = 9200,          // Windows 8.1
    .MaxBuildNumber = 26000,
    
    .IsBlocklisted = TRUE,           // Often blocklisted
    .WasTested = FALSE,
    .CanLoad = FALSE
};

// Dell BIOS driver - Dell update utility driver
static VULN_DRIVER_CONFIG g_DellBiosConfig = {
    .Type = VULN_DRIVER_DELL_BIOS,
    .Name = "Dell BIOS Driver",
    .DeviceName = "\\\\.\\DellBios",
    .ServiceNamePrefix = "dellbios",
    .DriverFileName = "dellbios.sys",
    
    .IoctlCode = 0x222004,
    
    .CaseMapPhysical = 0x222008,
    .CaseUnmapPhysical = 0x22200C,
    .CaseCopyMemory = 0x222010,
    .CaseAllocatePool = 0,           // Not supported
    .CaseGetPhysAddr = 0,
    .CaseMapIoSpace = 0x222008,
    
    .BufferSizeMap = 0x24,
    .BufferSizeCopy = 0x30,
    .BufferSizeUnmap = 0x20,
    .BufferSizeAlloc = 0,
    
    .UsesMdlMapping = FALSE,
    .RequiresPhysicalContiguous = TRUE,
    .SupportsKernelWrite = TRUE,
    .SupportsPoolAllocation = FALSE,
    .SupportsPhysicalTranslation = FALSE,
    
    .MaxMappingSize = 0x1000000,     // 16MB
    .AlignmentRequirement = 0x1000,
    
    .RequiresSecureBootDisabled = FALSE,
    .RequiresTestMode = FALSE,
    .RequiresDebugMode = FALSE,
    
    .MinBuildNumber = 10240,
    .MaxBuildNumber = 22000,
    
    .IsBlocklisted = FALSE,
    .WasTested = FALSE,
    .CanLoad = FALSE
};

// GLAZIO Intel Overclocking driver
static VULN_DRIVER_CONFIG g_GlazioConfig = {
    .Type = VULN_DRIVER_GLAZIO,
    .Name = "GLAZIO Intel Overclocking",
    .DeviceName = "\\\\.\\GLAZIO",
    .ServiceNamePrefix = "glazio",
    .DriverFileName = "GLAZIO.sys",
    
    .IoctlCode = 0x80862007,         // Similar to Intel NAL
    
    .CaseMapPhysical = 0x19,
    .CaseUnmapPhysical = 0x1A,
    .CaseCopyMemory = 0x33,
    .CaseAllocatePool = 0x25,
    .CaseGetPhysAddr = 0x26,
    .CaseMapIoSpace = 0x19,
    
    .BufferSizeMap = 0x30,
    .BufferSizeCopy = 0x30,
    .BufferSizeUnmap = 0x30,
    .BufferSizeAlloc = 0x30,
    
    .UsesMdlMapping = TRUE,
    .RequiresPhysicalContiguous = FALSE,
    .SupportsKernelWrite = TRUE,
    .SupportsPoolAllocation = TRUE,
    .SupportsPhysicalTranslation = TRUE,
    
    .MaxMappingSize = 0x10000000,    // 256MB
    .AlignmentRequirement = 0x1000,
    
    .RequiresSecureBootDisabled = FALSE,
    .RequiresTestMode = FALSE,
    .RequiresDebugMode = FALSE,
    
    .MinBuildNumber = 10240,
    .MaxBuildNumber = 26000,
    
    .IsBlocklisted = FALSE,
    .WasTested = FALSE,
    .CanLoad = FALSE
};

// Global array of all configurations
VULN_DRIVER_CONFIG g_VulnDriverConfigs[VULN_DRIVER_COUNT] = {0};

// Initialize the configuration array
static BOOL g_ConfigsInitialized = FALSE;

void InitDriverConfigs(void) {
    if (g_ConfigsInitialized) return;
    
    g_VulnDriverConfigs[VULN_DRIVER_INTEL_NAL] = g_IntelNalConfig;
    g_VulnDriverConfigs[VULN_DRIVER_GIGABYTE_GDRV] = g_GigabyteGdrvConfig;
    g_VulnDriverConfigs[VULN_DRIVER_ASROCK_RGB] = g_AsrockRgbConfig;
    g_VulnDriverConfigs[VULN_DRIVER_PROCESS_HACKER] = g_ProcessHackerConfig;
    g_VulnDriverConfigs[VULN_DRIVER_DELL_BIOS] = g_DellBiosConfig;
    g_VulnDriverConfigs[VULN_DRIVER_GLAZIO] = g_GlazioConfig;
    
    g_ConfigsInitialized = TRUE;
}

// Get configuration for a specific driver type
VULN_DRIVER_CONFIG* GetDriverConfig(VULN_DRIVER_TYPE type) {
    if (!g_ConfigsInitialized) InitDriverConfigs();
    
    if (type < 0 || type >= VULN_DRIVER_COUNT) {
        return NULL;
    }
    
    return &g_VulnDriverConfigs[type];
}

// Get driver type name
const char* GetDriverTypeName(VULN_DRIVER_TYPE type) {
    if (!g_ConfigsInitialized) InitDriverConfigs();
    
    if (type < 0 || type >= VULN_DRIVER_COUNT) {
        return "Unknown";
    }
    
    return g_VulnDriverConfigs[type].Name;
}

// Check if driver is compatible with current Windows build
BOOL IsDriverCompatible(VULN_DRIVER_CONFIG* config, ULONG currentBuild) {
    if (!config) return FALSE;
    
    if (config->MinBuildNumber > 0 && currentBuild < config->MinBuildNumber) {
        return FALSE;
    }
    
    if (config->MaxBuildNumber > 0 && currentBuild > config->MaxBuildNumber) {
        return FALSE;
    }
    
    return TRUE;
}

// Check if driver is available (not blocklisted, compatible, can be loaded)
BOOL IsDriverAvailable(VULN_DRIVER_CONFIG* config) {
    if (!config) return FALSE;
    
    // Already tested and can load
    if (config->WasTested && config->CanLoad) {
        return TRUE;
    }
    
    // Known to be blocklisted
    if (config->IsBlocklisted) {
        return FALSE;
    }
    
    // Need to check Windows version compatibility
    OSVERSIONINFOEXW osInfo = {0};
    osInfo.dwOSVersionInfoSize = sizeof(osInfo);
    
    typedef NTSTATUS (NTAPI *pRtlGetVersion)(PRTL_OSVERSIONINFOW);
    pRtlGetVersion RtlGetVersion = (pRtlGetVersion)GetProcAddress(
        GetModuleHandleA("ntdll.dll"), "RtlGetVersion");
    
    if (RtlGetVersion) {
        RtlGetVersion((PRTL_OSVERSIONINFOW)&osInfo);
        if (!IsDriverCompatible(config, osInfo.dwBuildNumber)) {
            return FALSE;
        }
    }
    
    return TRUE;
}

// Convenience functions for specific drivers
VULN_DRIVER_CONFIG* GetIntelNalConfig(void) {
    return GetDriverConfig(VULN_DRIVER_INTEL_NAL);
}

VULN_DRIVER_CONFIG* GetGigabyteGdrvConfig(void) {
    return GetDriverConfig(VULN_DRIVER_GIGABYTE_GDRV);
}

VULN_DRIVER_CONFIG* GetAsrockRgbConfig(void) {
    return GetDriverConfig(VULN_DRIVER_ASROCK_RGB);
}

VULN_DRIVER_CONFIG* GetProcessHackerConfig(void) {
    return GetDriverConfig(VULN_DRIVER_PROCESS_HACKER);
}

VULN_DRIVER_CONFIG* GetDellBiosConfig(void) {
    return GetDriverConfig(VULN_DRIVER_DELL_BIOS);
}

VULN_DRIVER_CONFIG* GetGlazioConfig(void) {
    return GetDriverConfig(VULN_DRIVER_GLAZIO);
}
