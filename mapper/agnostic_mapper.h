/*
 * Agnostic Mapper - Unified interface for multiple vulnerable drivers
 */

#ifndef AGNOSTIC_MAPPER_H
#define AGNOSTIC_MAPPER_H

#include "vuln_driver_config.h"
#include <windows.h>

#ifdef __cplusplus
extern "C" {
#endif

// Forward declarations
typedef struct _MAPPER_CONTEXT MAPPER_CONTEXT;

// Operation result codes
typedef enum _MAPPER_RESULT {
    MAPPER_SUCCESS = 0,
    MAPPER_ERROR_INVALID_PARAM,
    MAPPER_ERROR_DRIVER_NOT_FOUND,
    MAPPER_ERROR_DRIVER_BLOCKED,
    MAPPER_ERROR_DRIVER_LOAD_FAILED,
    MAPPER_ERROR_DEVICE_OPEN_FAILED,
    MAPPER_ERROR_MEMORY_ALLOCATION,
    MAPPER_ERROR_KERNEL_COMMUNICATION,
    MAPPER_ERROR_UNSUPPORTED_OPERATION,
    MAPPER_ERROR_INVALID_DRIVER_CONFIG,
    MAPPER_ERROR_SYSTEM_INCOMPATIBLE,
    MAPPER_ERROR_UNKNOWN
} MAPPER_RESULT;

// Mapper context - holds all state for a mapping session
typedef struct _MAPPER_CONTEXT {
    VULN_DRIVER_CONFIG* DriverConfig;
    HANDLE              hDevice;
    PVOID               KernelBase;
    BOOL                IsInitialized;
    BOOL                DriverLoaded;
    char                LastErrorMsg[512];
    MAPPER_RESULT       LastErrorCode;
    
    // Runtime driver path and service name
    char                DriverPath[MAX_PATH];
    char                ServiceName[32];
    char                DevicePath[64];
    
    // Original HalDispatchTable values (for cleanup)
    ULONG64             OriginalHalValue;
    BOOL                HalPatched;
} MAPPER_CONTEXT;

// Callback type for driver enumeration
typedef BOOL (*PFN_DRIVER_ENUM_CALLBACK)(VULN_DRIVER_CONFIG* config, PVOID userContext);

// ==================== CORE MAPPER API ====================

// Initialize mapper with a specific driver configuration
MAPPER_RESULT MapperInit(MAPPER_CONTEXT* ctx, VULN_DRIVER_TYPE driverType);

// Initialize with automatic driver selection (best available)
MAPPER_RESULT MapperInitAuto(MAPPER_CONTEXT* ctx);

// Cleanup mapper context and unload driver
void MapperCleanup(MAPPER_CONTEXT* ctx);

// Load the vulnerable driver
MAPPER_RESULT MapperLoadDriver(MAPPER_CONTEXT* ctx);

// Unload the vulnerable driver
MAPPER_RESULT MapperUnloadDriver(MAPPER_CONTEXT* ctx);

// Map a driver image into kernel memory
MAPPER_RESULT MapperMapImage(MAPPER_CONTEXT* ctx, PVOID imageBuffer, DWORD size, ULONG64* outEntryPoint);

// Execute driver entry point
MAPPER_RESULT MapperExecuteEntry(MAPPER_CONTEXT* ctx, ULONG64 entryAddr);

// Convenience: Full map + execute in one call
MAPPER_RESULT MapperMapAndExecute(MAPPER_CONTEXT* ctx, PVOID imageBuffer, DWORD size);

// ==================== MEMORY OPERATIONS ====================

// Read kernel memory
MAPPER_RESULT MapperReadKernelMemory(MAPPER_CONTEXT* ctx, ULONG64 kernelAddr, PVOID buffer, SIZE_T size);

// Write kernel memory
MAPPER_RESULT MapperWriteKernelMemory(MAPPER_CONTEXT* ctx, ULONG64 kernelAddr, PVOID buffer, SIZE_T size);

// Allocate kernel pool (if supported by driver)
MAPPER_RESULT MapperAllocateKernelPool(MAPPER_CONTEXT* ctx, SIZE_T size, ULONG64* outAddress);

// Get kernel base address
ULONG64 MapperGetKernelBase(MAPPER_CONTEXT* ctx);

// Translate virtual to physical address (if supported)
ULONG64 MapperTranslateVirtualToPhysical(MAPPER_CONTEXT* ctx, ULONG64 virtualAddr);

// ==================== UTILITY FUNCTIONS ====================

// Enumerate all available drivers
void MapperEnumerateDrivers(PFN_DRIVER_ENUM_CALLBACK callback, PVOID userContext);

// Get the best available driver type
VULN_DRIVER_TYPE MapperGetBestAvailableDriver(void);

// Get string description of error code
const char* MapperGetErrorString(MAPPER_RESULT result);

// Get last error message from context
const char* MapperGetLastError(MAPPER_CONTEXT* ctx);

// Check if a specific driver type can be used
BOOL MapperIsDriverAvailable(VULN_DRIVER_TYPE driverType);

// Test driver loading without full initialization
BOOL MapperTestDriverLoad(VULN_DRIVER_TYPE driverType);

// ==================== HELPER MACROS ====================

#define MAPPER_CHECK_INITIALIZED(ctx) \
    do { if (!(ctx) || !(ctx)->IsInitialized) return MAPPER_ERROR_INVALID_PARAM; } while(0)

#define MAPPER_SET_ERROR(ctx, code, msg) \
    do { (ctx)->LastErrorCode = (code); strncpy_s((ctx)->LastErrorMsg, sizeof((ctx)->LastErrorMsg), (msg), _TRUNCATE); } while(0)

#ifdef __cplusplus
}
#endif

#endif // AGNOSTIC_MAPPER_H
