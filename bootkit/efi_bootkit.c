/*
 * EFI Bootkit Implementation
 * UEFI Pre-OS Driver Loader
 */

#include "efi_bootkit.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <shlobj.h>
#include <wchar.h>
#include "../manager/resource.h"

#pragma comment(lib, "shell32.lib")
#pragma comment(lib, "advapi32.lib")

// EFI partition path
#define EFI_BOOTKIT_DIR         "\\EFI\\HWIDSpoofer"
#define EFI_BOOTKIT_APP         "\\EFI\\HWIDSpoofer\\bootkit.efi"
#define EFI_BOOTKIT_DRIVER      "\\EFI\\HWIDSpoofer\\spoofer.sys"
#define EFI_BOOTKIT_CONFIG      "\\EFI\\HWIDSpoofer\\config.bin"
#define EFI_BOOTKIT_INFO        "\\EFI\\HWIDSpoofer\\install.dat"

// Windows BCD constants
#define BCD_EDIT_PATH           "C:\\Windows\\System32\\bcdedit.exe"

// GUID for bootkit entry
#define BOOTKIT_ENTRY_GUID      "{a593b0c1-e57e-4e45-8043-a5d2f44e4e2c}"

// ==================== HELPER FUNCTIONS ====================

// Execute command and capture output
static BOOL ExecuteCommand(const char* cmd, char* output, size_t outputSize) {
    SECURITY_ATTRIBUTES sa;
    HANDLE hRead, hWrite;
    PROCESS_INFORMATION pi;
    STARTUPINFOA si;
    
    sa.nLength = sizeof(SECURITY_ATTRIBUTES);
    sa.lpSecurityDescriptor = NULL;
    sa.bInheritHandle = TRUE;
    
    if (!CreatePipe(&hRead, &hWrite, &sa, 0)) return FALSE;
    
    ZeroMemory(&si, sizeof(si));
    si.cb = sizeof(si);
    si.hStdError = hWrite;
    si.hStdOutput = hWrite;
    si.dwFlags = STARTF_USESTDHANDLES;
    
    ZeroMemory(&pi, sizeof(pi));
    
    char cmdLine[1024];
    sprintf_s(cmdLine, sizeof(cmdLine), "cmd.exe /c %s", cmd);
    
    BOOL success = CreateProcessA(NULL, cmdLine, NULL, NULL, TRUE,
        CREATE_NO_WINDOW, NULL, NULL, &si, &pi);
    
    CloseHandle(hWrite);
    
    if (success) {
        WaitForSingleObject(pi.hProcess, INFINITE);
        
        if (output && outputSize > 0) {
            DWORD bytesRead = 0;
            ReadFile(hRead, output, (DWORD)outputSize - 1, &bytesRead, NULL);
            output[bytesRead] = '\0';
        }
        
        CloseHandle(pi.hProcess);
        CloseHandle(pi.hThread);
    }
    
    CloseHandle(hRead);
    return success;
}

// Check if running on EFI system
BOOL BootkitIsEfiSystem(void) {
    // Check for EFI firmware environment
    HANDLE hToken = NULL;
    TOKEN_ELEVATION elevation;
    DWORD dwSize = 0;
    
    // Check if we can access EFI system partition (indicates UEFI)
    DWORD firmwareType = 0;
    HMODULE hKernel = GetModuleHandleA("kernel32.dll");
    if (hKernel) {
        typedef DWORD (WINAPI *pGetFirmwareType)(DWORD*);
        pGetFirmwareType GetFirmwareType = (pGetFirmwareType)GetProcAddress(hKernel, "GetFirmwareType");
        if (GetFirmwareType) {
            GetFirmwareType(&firmwareType);
            // FirmwareTypeUefi = 2
            return firmwareType == 2;
        }
    }
    
    // Fallback: Check if legacy BIOS boot
    // Look for bootmgr on EFI partition
    char output[256];
    if (ExecuteCommand("bcdedit /enum {fwbootmgr}", output, sizeof(output))) {
        return strstr(output, "fwbootmgr") != NULL;
    }
    
    return FALSE;
}

// Check Secure Boot status
BOOL BootkitIsSecureBootEnabled(void) {
    HKEY hKey;
    DWORD value = 1;  // Default to enabled (safe)
    DWORD size = sizeof(value);
    
    if (RegOpenKeyExA(HKEY_LOCAL_MACHINE,
            "SYSTEM\\CurrentControlSet\\Control\\SecureBoot\\State",
            0, KEY_READ, &hKey) == ERROR_SUCCESS) {
        if (RegQueryValueExA(hKey, "UEFISecureBootEnabled", NULL, NULL, 
            (LPBYTE)&value, &size) != ERROR_SUCCESS) {
            value = 1;
        }
        RegCloseKey(hKey);
        return value != 0;
    }
    
    return TRUE;  // Assume enabled on error
}

// Mount EFI partition
BOOL BootkitMountEfiPartition(char driveLetter[4]) {
    char output[1024];
    
    // Use mountvol to get EFI partition path
    if (!ExecuteCommand("mountvol", output, sizeof(output))) {
        return FALSE;
    }
    
    // Find EFI system partition (ESP) in output
    // Format: \\?\Volume{GUID}
    char* espStart = strstr(output, "*** NO MOUNT POINTS ***");
    if (!espStart) {
        return FALSE;
    }
    
    // Find a free drive letter (try S: first)
    const char* tryLetters = "STUVWXYZ";
    for (int i = 0; tryLetters[i]; i++) {
        char testPath[4];
        sprintf_s(testPath, sizeof(testPath), "%c:\\", tryLetters[i]);
        
        UINT driveType = GetDriveTypeA(testPath);
        if (driveType == DRIVE_NO_ROOT_DIR) {
            // Drive letter is free, try to mount
            char mountCmd[256];
            sprintf_s(mountCmd, sizeof(mountCmd), 
                "mountvol %c: /s", tryLetters[i]);
            
            if (ExecuteCommand(mountCmd, NULL, 0)) {
                sprintf_s(driveLetter, 4, "%c:", tryLetters[i]);
                return TRUE;
            }
        }
    }
    
    return FALSE;
}

// Unmount EFI partition
BOOL BootkitUnmountEfiPartition(const char driveLetter[4]) {
    char cmd[256];
    sprintf_s(cmd, sizeof(cmd), "mountvol %s /d", driveLetter);
    return ExecuteCommand(cmd, NULL, 0);
}

// Get Windows boot entry ID
BOOL BootkitGetWindowsBootEntry(char* bootId, size_t bootIdSize) {
    char output[4096];
    
    if (!ExecuteCommand("bcdedit /enum", output, sizeof(output))) {
        return FALSE;
    }
    
    // Look for Windows Boot Manager entry
    char* entryStart = strstr(output, "Windows Boot Manager");
    if (!entryStart) {
        entryStart = strstr(output, "Windows Boot Loader");
    }
    if (!entryStart) {
        return FALSE;
    }
    
    // Find identifier line before this
    char* searchPtr = output;
    char* lastIdentifier = NULL;
    
    while (searchPtr < entryStart) {
        char* idPos = strstr(searchPtr, "identifier");
        if (idPos && idPos < entryStart) {
            lastIdentifier = idPos;
            searchPtr = idPos + 1;
        } else {
            break;
        }
    }
    
    if (lastIdentifier) {
        // Extract GUID
        char* guidStart = strchr(lastIdentifier, '{');
        if (guidStart) {
            char* guidEnd = strchr(guidStart, '}');
            if (guidEnd) {
                size_t len = guidEnd - guidStart + 1;
                if (len < bootIdSize) {
                    strncpy_s(bootId, bootIdSize, guidStart, len);
                    bootId[len] = '\0';
                    return TRUE;
                }
            }
        }
    }
    
    return FALSE;
}

// Create bootkit directory structure
static BOOL CreateBootkitDirectories(const char* efiDrive) {
    char path[MAX_PATH];
    
    // Create EFI\HWIDSpoofer directory
    sprintf_s(path, sizeof(path), "%s%s", efiDrive, EFI_BOOTKIT_DIR);
    
    // Create directory using CreateDirectoryA (may need multiple levels)
    char* p = path + 3;  // Skip "X:\"
    while (*p) {
        if (*p == '\\') {
            *p = '\0';
            CreateDirectoryA(path, NULL);
            *p = '\\';
        }
        p++;
    }
    CreateDirectoryA(path, NULL);
    
    return GetFileAttributesA(path) != INVALID_FILE_ATTRIBUTES;
}

// Write embedded EFI application
BOOL BootkitCopyEfiApplication(const char* efiPartitionDrive) {
    char efiPath[MAX_PATH];
    sprintf_s(efiPath, sizeof(efiPath), "%s%s", efiPartitionDrive, EFI_BOOTKIT_APP);
    
    HMODULE hMod = GetModuleHandle(NULL);
    HRSRC hRes = FindResourceA(hMod, MAKEINTRESOURCEA(IDR_BOOTKIT_EFI), RT_RCDATA);
    if (!hRes) return FALSE;

    HGLOBAL hData = LoadResource(hMod, hRes);
    DWORD size = SizeofResource(hMod, hRes);
    PVOID data = LockResource(hData);

    if (!data || size == 0) return FALSE;

    HANDLE hFile = CreateFileA(efiPath, GENERIC_WRITE, 0, NULL, 
        CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    if (hFile == INVALID_HANDLE_VALUE) return FALSE;

    DWORD written = 0;
    BOOL success = WriteFile(hFile, data, size, &written, NULL);
    CloseHandle(hFile);

    return success && (written == size);
}

// Write driver image to EFI partition
BOOL BootkitWriteDriverImage(const char* efiPartitionDrive, 
    const BYTE* driverImage, DWORD driverSize) {
    
    if (!driverImage || driverSize == 0) return FALSE;
    
    char driverPath[MAX_PATH];
    sprintf_s(driverPath, sizeof(driverPath), "%s%s", efiPartitionDrive, EFI_BOOTKIT_DRIVER);
    
    HANDLE hFile = CreateFileA(driverPath, GENERIC_WRITE, 0, NULL, 
        CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    
    if (hFile == INVALID_HANDLE_VALUE) return FALSE;
    
    DWORD written = 0;
    BOOL success = WriteFile(hFile, driverImage, driverSize, &written, NULL);
    CloseHandle(hFile);
    
    return success && (written == driverSize);
}

// Write bootkit configuration
BOOL BootkitWriteConfig(const char* efiPartitionDrive, 
    const BOOTKIT_CONFIG* config) {
    
    if (!config || config->Magic != EFI_BOOTKIT_MAGIC) return FALSE;
    
    char configPath[MAX_PATH];
    sprintf_s(configPath, sizeof(configPath), "%s%s", efiPartitionDrive, EFI_BOOTKIT_CONFIG);
    
    HANDLE hFile = CreateFileA(configPath, GENERIC_WRITE, 0, NULL,
        CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    
    if (hFile == INVALID_HANDLE_VALUE) return FALSE;
    
    DWORD written = 0;
    BOOL success = WriteFile(hFile, config, sizeof(BOOTKIT_CONFIG), &written, NULL);
    CloseHandle(hFile);
    
    return success && (written == sizeof(BOOTKIT_CONFIG));
}

// Add bootkit entry to BCD
BOOL BootkitAddBcdEntry(const char* efiPartitionDrive) {
    char cmd[512];
    
    // First, remove any existing entry
    BootkitRemoveBcdEntry();
    
    // Create new boot entry
    sprintf_s(cmd, sizeof(cmd), 
        "bcdedit /create %s /d \"HWID Spoofer Bootkit\" /application osloader",
        BOOTKIT_ENTRY_GUID);
    
    if (!ExecuteCommand(cmd, NULL, 0)) {
        return FALSE;
    }
    
    // Set device to EFI partition
    sprintf_s(cmd, sizeof(cmd),
        "bcdedit /set %s device partition=%s",
        BOOTKIT_ENTRY_GUID, efiPartitionDrive);
    if (!ExecuteCommand(cmd, NULL, 0)) return FALSE;
    
    // Set path to EFI application
    sprintf_s(cmd, sizeof(cmd),
        "bcdedit /set %s path %s",
        BOOTKIT_ENTRY_GUID, EFI_BOOTKIT_APP);
    if (!ExecuteCommand(cmd, NULL, 0)) return FALSE;
    
    // Set description
    sprintf_s(cmd, sizeof(cmd),
        "bcdedit /set %s description \"HWID Spoofer Bootkit (Pre-OS Driver)\"",
        BOOTKIT_ENTRY_GUID);
    ExecuteCommand(cmd, NULL, 0);
    
    return TRUE;
}

// Remove bootkit entry from BCD
BOOL BootkitRemoveBcdEntry(void) {
    char cmd[256];
    sprintf_s(cmd, sizeof(cmd), "bcdedit /delete %s /f", BOOTKIT_ENTRY_GUID);
    return ExecuteCommand(cmd, NULL, 0);
}

// Set bootkit as default
BOOL BootkitSetAsDefaultBoot(BOOL setAsDefault) {
    if (setAsDefault) {
        char cmd[256];
        sprintf_s(cmd, sizeof(cmd), "bcdedit /default %s", BOOTKIT_ENTRY_GUID);
        return ExecuteCommand(cmd, NULL, 0);
    } else {
        // Reset to Windows boot manager
        return ExecuteCommand("bcdedit /default {bootmgr}", NULL, 0);
    }
}

// ==================== PUBLIC API ====================

// Get bootkit status
BOOTKIT_STATUS BootkitGetStatus(void) {
    // Check if bootkit is installed
    char efiDrive[4] = {0};
    
    if (!BootkitMountEfiPartition(efiDrive)) {
        return BOOTKIT_STATUS_NOT_INSTALLED;
    }
    
    // Check for bootkit files
    char checkPath[MAX_PATH];
    sprintf_s(checkPath, sizeof(checkPath), "%s%s", efiDrive, EFI_BOOTKIT_APP);
    
    BOOL hasApp = GetFileAttributesA(checkPath) != INVALID_FILE_ATTRIBUTES;
    
    sprintf_s(checkPath, sizeof(checkPath), "%s%s", efiDrive, EFI_BOOTKIT_CONFIG);
    BOOL hasConfig = GetFileAttributesA(checkPath) != INVALID_FILE_ATTRIBUTES;
    
    BootkitUnmountEfiPartition(efiDrive);
    
    if (hasApp && hasConfig) {
        // Check if it's set as default
        char output[1024];
        if (ExecuteCommand("bcdedit /enum", output, sizeof(output))) {
            if (strstr(output, BOOTKIT_ENTRY_GUID)) {
                return BOOTKIT_STATUS_INSTALLED_ACTIVE;
            }
        }
        return BOOTKIT_STATUS_INSTALLED_INACTIVE;
    }
    
    return BOOTKIT_STATUS_NOT_INSTALLED;
}

// Install bootkit
BOOTKIT_RESULT BootkitInstall(const BOOTKIT_CONFIG* config) {
    if (!config) {
        return BOOTKIT_ERROR_INVALID_IMAGE;
    }
    
    // Verify EFI system
    if (!BootkitIsEfiSystem()) {
        return BOOTKIT_ERROR_NOT_EFI_SYSTEM;
    }
    
    // Check if already installed
    if (BootkitGetStatus() == BOOTKIT_STATUS_INSTALLED_ACTIVE ||
        BootkitGetStatus() == BOOTKIT_STATUS_INSTALLED_INACTIVE) {
        return BOOTKIT_ERROR_ALREADY_INSTALLED;
    }
    
    // Check admin privileges
    HANDLE hToken = NULL;
    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &hToken)) {
        return BOOTKIT_ERROR_ACCESS_DENIED;
    }
    
    TOKEN_ELEVATION elevation;
    DWORD dwSize = sizeof(elevation);
    BOOL isAdmin = FALSE;
    
    if (GetTokenInformation(hToken, TokenElevation, &elevation, sizeof(elevation), &dwSize)) {
        isAdmin = elevation.TokenIsElevated;
    }
    CloseHandle(hToken);
    
    if (!isAdmin) {
        return BOOTKIT_ERROR_ACCESS_DENIED;
    }
    
    // Mount EFI partition
    char efiDrive[4] = {0};
    if (!BootkitMountEfiPartition(efiDrive)) {
        return BOOTKIT_ERROR_NO_EFI_PARTITION;
    }
    
    // Create directories
    if (!CreateBootkitDirectories(efiDrive)) {
        BootkitUnmountEfiPartition(efiDrive);
        return BOOTKIT_ERROR_MOUNT_FAILED;
    }
    
    // Copy EFI application
    if (!BootkitCopyEfiApplication(efiDrive)) {
        BootkitUnmountEfiPartition(efiDrive);
        return BOOTKIT_ERROR_FILE_COPY_FAILED;
    }
    
    // Write driver image if provided
    if (config->DriverImage && config->DriverSize > 0) {
        if (!BootkitWriteDriverImage(efiDrive, config->DriverImage, config->DriverSize)) {
            BootkitUnmountEfiPartition(efiDrive);
            return BOOTKIT_ERROR_FILE_COPY_FAILED;
        }
    }
    
    // Write configuration
    if (!BootkitWriteConfig(efiDrive, config)) {
        BootkitUnmountEfiPartition(efiDrive);
        return BOOTKIT_ERROR_FILE_COPY_FAILED;
    }
    
    // Add BCD entry
    if (!BootkitAddBcdEntry(efiDrive)) {
        BootkitUnmountEfiPartition(efiDrive);
        return BOOTKIT_ERROR_BCD_EDIT_FAILED;
    }
    
    // Set as default if requested
    if (config->Flags & BOOTKIT_FLAG_CHAINLOAD_WIN) {
        BootkitSetAsDefaultBoot(TRUE);
    }
    
    // Unmount EFI partition
    BootkitUnmountEfiPartition(efiDrive);
    
    return BOOTKIT_SUCCESS;
}

// Uninstall bootkit
BOOTKIT_RESULT BootkitUninstall(void) {
    // Remove BCD entry
    BootkitRemoveBcdEntry();
    
    // Mount EFI partition
    char efiDrive[4] = {0};
    if (!BootkitMountEfiPartition(efiDrive)) {
        return BOOTKIT_ERROR_NO_EFI_PARTITION;
    }
    
    // Remove bootkit directory (recursively)
    char bootkitDir[MAX_PATH];
    sprintf_s(bootkitDir, sizeof(bootkitDir), "%s%s", efiDrive, EFI_BOOTKIT_DIR);
    
    // Delete files
    char filePath[MAX_PATH];
    sprintf_s(filePath, sizeof(filePath), "%s%s", efiDrive, EFI_BOOTKIT_APP);
    DeleteFileA(filePath);
    
    sprintf_s(filePath, sizeof(filePath), "%s%s", efiDrive, EFI_BOOTKIT_DRIVER);
    DeleteFileA(filePath);
    
    sprintf_s(filePath, sizeof(filePath), "%s%s", efiDrive, EFI_BOOTKIT_CONFIG);
    DeleteFileA(filePath);
    
    sprintf_s(filePath, sizeof(filePath), "%s%s", efiDrive, EFI_BOOTKIT_INFO);
    DeleteFileA(filePath);
    
    // Remove directory
    RemoveDirectoryA(bootkitDir);
    
    BootkitUnmountEfiPartition(efiDrive);
    
    return BOOTKIT_SUCCESS;
}

// Update driver image
BOOTKIT_RESULT BootkitUpdateDriver(const BYTE* driverImage, DWORD driverSize) {
    if (!driverImage || driverSize == 0) {
        return BOOTKIT_ERROR_INVALID_IMAGE;
    }
    
    BOOTKIT_STATUS status = BootkitGetStatus();
    if (status == BOOTKIT_STATUS_NOT_INSTALLED) {
        return BOOTKIT_ERROR_NOT_INSTALLED;
    }
    
    char efiDrive[4] = {0};
    if (!BootkitMountEfiPartition(efiDrive)) {
        return BOOTKIT_ERROR_NO_EFI_PARTITION;
    }
    
    BOOL success = BootkitWriteDriverImage(efiDrive, driverImage, driverSize);
    
    BootkitUnmountEfiPartition(efiDrive);
    
    return success ? BOOTKIT_SUCCESS : BOOTKIT_ERROR_FILE_COPY_FAILED;
}

// Enable/disable bootkit
BOOTKIT_RESULT BootkitSetEnabled(BOOL enabled) {
    BOOTKIT_STATUS status = BootkitGetStatus();
    
    if (status == BOOTKIT_STATUS_NOT_INSTALLED) {
        return BOOTKIT_ERROR_NOT_INSTALLED;
    }
    
    if (enabled) {
        if (status == BOOTKIT_STATUS_INSTALLED_ACTIVE) {
            return BOOTKIT_SUCCESS;  // Already enabled
        }
        
        char efiDrive[4] = {0};
        if (!BootkitMountEfiPartition(efiDrive)) {
            return BOOTKIT_ERROR_NO_EFI_PARTITION;
        }
        
        BOOL success = BootkitAddBcdEntry(efiDrive);
        if (success) {
            BootkitSetAsDefaultBoot(TRUE);
        }
        
        BootkitUnmountEfiPartition(efiDrive);
        return success ? BOOTKIT_SUCCESS : BOOTKIT_ERROR_BCD_EDIT_FAILED;
    } else {
        if (status == BOOTKIT_STATUS_INSTALLED_INACTIVE) {
            return BOOTKIT_SUCCESS;  // Already disabled
        }
        
        BootkitSetAsDefaultBoot(FALSE);
        return BOOTKIT_SUCCESS;
    }
}

// Get error string
const char* BootkitGetErrorString(BOOTKIT_RESULT result) {
    switch (result) {
        case BOOTKIT_SUCCESS:               return "Success";
        case BOOTKIT_ERROR_NOT_EFI_SYSTEM:  return "System is not using EFI/UEFI";
        case BOOTKIT_ERROR_ACCESS_DENIED:   return "Administrator privileges required";
        case BOOTKIT_ERROR_NO_EFI_PARTITION: return "Could not access EFI System Partition";
        case BOOTKIT_ERROR_MOUNT_FAILED:    return "Failed to mount EFI partition";
        case BOOTKIT_ERROR_FILE_COPY_FAILED: return "Failed to copy bootkit files";
        case BOOTKIT_ERROR_BCD_EDIT_FAILED: return "Failed to modify boot configuration";
        case BOOTKIT_ERROR_ALREADY_INSTALLED: return "Bootkit is already installed";
        case BOOTKIT_ERROR_NOT_INSTALLED:   return "Bootkit is not installed";
        case BOOTKIT_ERROR_INVALID_IMAGE:   return "Invalid driver image or configuration";
        case BOOTKIT_ERROR_UNKNOWN:         return "Unknown error";
        default:                            return "Undefined error code";
    }
}

// Get installation info
BOOL BootkitGetInstallInfo(BOOTKIT_INSTALL_INFO* info) {
    if (!info) return FALSE;
    
    char efiDrive[4] = {0};
    if (!BootkitMountEfiPartition(efiDrive)) {
        return FALSE;
    }
    
    char infoPath[MAX_PATH];
    sprintf_s(infoPath, sizeof(infoPath), "%s%s", efiDrive, EFI_BOOTKIT_INFO);
    
    HANDLE hFile = CreateFileA(infoPath, GENERIC_READ, FILE_SHARE_READ, NULL,
        OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    
    if (hFile == INVALID_HANDLE_VALUE) {
        BootkitUnmountEfiPartition(efiDrive);
        return FALSE;
    }
    
    DWORD read = 0;
    BOOL success = ReadFile(hFile, info, sizeof(BOOTKIT_INSTALL_INFO), &read, NULL);
    CloseHandle(hFile);
    BootkitUnmountEfiPartition(efiDrive);
    
    if (!success || read != sizeof(BOOTKIT_INSTALL_INFO)) {
        return FALSE;
    }
    
    // Verify magic
    if (info->Magic != EFI_BOOTKIT_MAGIC) {
        return FALSE;
    }
    
    return TRUE;
}
