#ifndef EFI_BOOTKIT_H
#define EFI_BOOTKIT_H

/*
 * EFI Bootkit - UEFI Pre-OS Driver Loader
 * 
 * This bootkit executes before Windows kernel initializes,
 * allowing us to load drivers without DSE (Driver Signature Enforcement).
 */

#include <windows.h>

#ifdef __cplusplus
extern "C" {
#endif

// EFI Bootkit version
#define EFI_BOOTKIT_VERSION     0x00010000  // 1.0.0
#define EFI_BOOTKIT_MAGIC       0x424F4F54  // "BOOT"

// Bootkit configuration flags
typedef enum _BOOTKIT_FLAGS {
    BOOTKIT_FLAG_NONE           = 0x0000,
    BOOTKIT_FLAG_CHAINLOAD_WIN  = 0x0001,  // Chainload Windows after driver load
    BOOTKIT_FLAG_SKIP_DRIVER    = 0x0002,  // Skip driver loading (debug)
    BOOTKIT_FLAG_VERBOSE        = 0x0004,  // Verbose output
    BOOTKIT_FLAG_FORCE_LEGACY   = 0x0008,  // Force legacy boot path
    BOOTKIT_FLAG_PERSISTENT     = 0x0010,  // Make installation persistent
} BOOTKIT_FLAGS;

// Bootkit installation result
typedef enum _BOOTKIT_RESULT {
    BOOTKIT_SUCCESS = 0,
    BOOTKIT_ERROR_NOT_EFI_SYSTEM,
    BOOTKIT_ERROR_ACCESS_DENIED,
    BOOTKIT_ERROR_NO_EFI_PARTITION,
    BOOTKIT_ERROR_MOUNT_FAILED,
    BOOTKIT_ERROR_FILE_COPY_FAILED,
    BOOTKIT_ERROR_BCD_EDIT_FAILED,
    BOOTKIT_ERROR_ALREADY_INSTALLED,
    BOOTKIT_ERROR_NOT_INSTALLED,
    BOOTKIT_ERROR_INVALID_IMAGE,
    BOOTKIT_ERROR_UNKNOWN
} BOOTKIT_RESULT;

// Bootkit state/status
typedef enum _BOOTKIT_STATUS {
    BOOTKIT_STATUS_UNKNOWN = 0,
    BOOTKIT_STATUS_NOT_INSTALLED,
    BOOTKIT_STATUS_INSTALLED_ACTIVE,
    BOOTKIT_STATUS_INSTALLED_INACTIVE,
    BOOTKIT_STATUS_PENDING_REBOOT,
    BOOTKIT_STATUS_ERROR,
} BOOTKIT_STATUS;

// Bootkit configuration structure
typedef struct _BOOTKIT_CONFIG {
    DWORD       Magic;              // Must be EFI_BOOTKIT_MAGIC
    DWORD       Version;            // BOOTKIT_VERSION
    DWORD       Flags;              // BOOTKIT_FLAGS combination
    
    // Driver image to load
    BYTE*       DriverImage;
    DWORD       DriverSize;
    
    // Driver entry parameters
    PVOID       DriverContext;
    
    // Boot timeout (seconds)
    DWORD       BootTimeout;
    
    // Reserved for future use
    BYTE        Reserved[64];
} BOOTKIT_CONFIG;

// Bootkit installation info (stored in EFI partition)
typedef struct _BOOTKIT_INSTALL_INFO {
    DWORD       Magic;
    DWORD       Version;
    ULONGLONG   InstallTime;
    ULONGLONG   LastBootTime;
    DWORD       BootCount;
    DWORD       Flags;
    CHAR        DriverName[64];
    BYTE        DriverHash[32];     // SHA256 hash of driver
    BYTE        Reserved[128];
} BOOTKIT_INSTALL_INFO;

// ==================== INSTALLATION API ====================

// Check if system is EFI-based
BOOL BootkitIsEfiSystem(void);

// Get current bootkit status
BOOTKIT_STATUS BootkitGetStatus(void);

// Install bootkit to EFI partition
BOOTKIT_RESULT BootkitInstall(const BOOTKIT_CONFIG* config);

// Uninstall bootkit from EFI partition
BOOTKIT_RESULT BootkitUninstall(void);

// Update bootkit driver image
BOOTKIT_RESULT BootkitUpdateDriver(const BYTE* driverImage, DWORD driverSize);

// Enable/disable bootkit without uninstalling
BOOTKIT_RESULT BootkitSetEnabled(BOOL enabled);

// Get detailed error string for result
const char* BootkitGetErrorString(BOOTKIT_RESULT result);

// Get installation info (if installed)
BOOL BootkitGetInstallInfo(BOOTKIT_INSTALL_INFO* info);

// ==================== UTILITY FUNCTIONS ====================

// Mount EFI partition (returns drive letter)
BOOL BootkitMountEfiPartition(char driveLetter[4]);

// Unmount EFI partition
BOOL BootkitUnmountEfiPartition(const char driveLetter[4]);

// Check if Secure Boot is enabled (must be disabled for bootkit)
BOOL BootkitIsSecureBootEnabled(void);

// Get Windows boot entry ID
BOOL BootkitGetWindowsBootEntry(char* bootId, size_t bootIdSize);

// ==================== INTERNAL HELPERS ====================

// Copy bootkit EFI application to ESP
BOOL BootkitCopyEfiApplication(const char* efiPartitionDrive);

// Write driver image to ESP
BOOL BootkitWriteDriverImage(const char* efiPartitionDrive, 
    const BYTE* driverImage, DWORD driverSize);

// Write bootkit configuration to ESP
BOOL BootkitWriteConfig(const char* efiPartitionDrive, 
    const BOOTKIT_CONFIG* config);

// Update BCD to add bootkit entry
BOOL BootkitAddBcdEntry(const char* efiPartitionDrive);

// Remove BCD bootkit entry
BOOL BootkitRemoveBcdEntry(void);

// Set bootkit as default boot entry
BOOL BootkitSetAsDefaultBoot(BOOL setAsDefault);

#ifdef __cplusplus
}
#endif

#endif // EFI_BOOTKIT_H
