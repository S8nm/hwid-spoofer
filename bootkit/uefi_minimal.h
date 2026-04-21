#ifndef UEFI_MINIMAL_H
#define UEFI_MINIMAL_H

// Minimal UEFI Definitions for MSVC Native Compilation
typedef unsigned long long UINT64;
typedef long long          INT64;
typedef unsigned int       UINT32;
typedef int                INT32;
typedef unsigned short     UINT16;
typedef short              INT16;
typedef unsigned char      UINT8;
typedef char               INT8;
typedef unsigned char      BOOLEAN;
typedef void*              EFI_HANDLE;
typedef UINT64             EFI_PHYSICAL_ADDRESS;
typedef UINT64             EFI_VIRTUAL_ADDRESS;
typedef void               VOID;

#ifndef NULL
#define NULL ((void*)0)
#endif

#ifdef _WIN64
typedef UINT64 UINTN;
typedef INT64  INTN;
#else
typedef UINT32 UINTN;
typedef INT32  INTN;
#endif

typedef UINT16 CHAR16;

#define EFI_SUCCESS 0
#define EFIAPI __cdecl // UEFI uses __cdecl or Microsoft ABI on x64 (which is the default __fastcall)
#ifdef _WIN64
#undef EFIAPI
#define EFIAPI
#endif

typedef UINTN EFI_STATUS;
#define EFI_ERROR(x) ((INTN)(x) < 0)

// ---------------- EFI Table Headers ----------------
typedef struct {
    UINT64 Signature;
    UINT32 Revision;
    UINT32 HeaderSize;
    UINT32 CRC32;
    UINT32 Reserved;
} EFI_TABLE_HEADER;

// ---------------- Forward Declarations ----------------
struct _EFI_SYSTEM_TABLE;
struct _EFI_BOOT_SERVICES;

// ---------------- EFI Protocols ----------------
typedef struct {
    UINT32 Data1;
    UINT16 Data2;
    UINT16 Data3;
    UINT8  Data4[8];
} EFI_GUID;

extern EFI_GUID gEfiLoadedImageProtocolGuid;

typedef struct {
    UINT32            Revision;
    EFI_HANDLE        ParentHandle;
    struct _EFI_SYSTEM_TABLE *SystemTable;
    EFI_HANDLE        DeviceHandle;
    void              *FilePath;
    void              *Reserved;
    UINT32            LoadOptionsSize;
    void              *LoadOptions;
    void              *ImageBase;
    UINT64            ImageSize;
    // ... we don't need the rest for now
} EFI_LOADED_IMAGE;

// ---------------- Boot Services ----------------
typedef EFI_STATUS (EFIAPI *EFI_START_IMAGE)(EFI_HANDLE ImageHandle, UINTN *ExitDataSize, CHAR16 **ExitData);
typedef EFI_STATUS (EFIAPI *EFI_HANDLE_PROTOCOL)(EFI_HANDLE Handle, EFI_GUID *Protocol, void **Interface);

// Minimal BS Table
typedef struct _EFI_BOOT_SERVICES {
    EFI_TABLE_HEADER Hdr;
    // Task Priority Services
    void* RaiseTPL;
    void* RestoreTPL;
    // Memory Services
    void* AllocatePages;
    void* FreePages;
    void* GetMemoryMap;
    void* AllocatePool;
    void* FreePool;
    // Event & Timer Services
    void* CreateEvent;
    void* SetTimer;
    void* WaitForEvent;
    void* SignalEvent;
    void* CloseEvent;
    void* CheckEvent;
    // Protocol Handler Services
    void* InstallProtocolInterface;
    void* ReinstallProtocolInterface;
    void* UninstallProtocolInterface;
    EFI_HANDLE_PROTOCOL HandleProtocol;
    void* Reserved;
    void* RegisterProtocolNotify;
    void* LocateHandle;
    void* LocateDevicePath;
    void* InstallConfigurationTable;
    // Image Services
    void* LoadImage;
    EFI_START_IMAGE StartImage;
    void* Exit;
    void* UnloadImage;
    void* ExitBootServices;
    // Misc
    void* GetNextMonotonicCount;
    void* Stall;
    void* SetWatchdogTimer;
    // ...
} EFI_BOOT_SERVICES;

typedef struct _EFI_RUNTIME_SERVICES {
    EFI_TABLE_HEADER Hdr;
    void* GetTime;
    void* SetTime;
    void* GetWakeupTime;
    void* SetWakeupTime;
    void* SetVirtualAddressMap;
    void* ConvertPointer;
    void* GetVariable;
    void* GetNextVariableName;
    void* SetVariable;
    void* GetNextHighMonotonicCount;
    void* ResetSystem;
} EFI_RUNTIME_SERVICES;

typedef struct _EFI_SIMPLE_TEXT_OUTPUT_PROTOCOL {
    void* Reset;
    EFI_STATUS (EFIAPI *OutputString)(struct _EFI_SIMPLE_TEXT_OUTPUT_PROTOCOL *This, CHAR16 *String);
    void* TestString;
    void* QueryMode;
    void* SetMode;
    void* SetAttribute;
    void* ClearScreen;
    void* SetCursorPosition;
    void* EnableCursor;
    void* Mode;
} EFI_SIMPLE_TEXT_OUTPUT_PROTOCOL;

typedef struct _EFI_SYSTEM_TABLE {
    EFI_TABLE_HEADER                 Hdr;
    CHAR16                           *FirmwareVendor;
    UINT32                           FirmwareRevision;
    EFI_HANDLE                       ConsoleInHandle;
    void                             *ConIn;
    EFI_HANDLE                       ConsoleOutHandle;
    EFI_SIMPLE_TEXT_OUTPUT_PROTOCOL  *ConOut;
    EFI_HANDLE                       StandardErrorHandle;
    EFI_SIMPLE_TEXT_OUTPUT_PROTOCOL  *StdErr;
    EFI_RUNTIME_SERVICES             *RuntimeServices;
    EFI_BOOT_SERVICES                *BootServices;
    UINTN                            NumberOfTableEntries;
    void                             *ConfigurationTable;
} EFI_SYSTEM_TABLE;

// ---------------- Helpers ----------------
static EFI_SYSTEM_TABLE *gST = 0;
static EFI_BOOT_SERVICES *gBS = 0;

static inline void Print(CHAR16 *Str) {
    if (gST && gST->ConOut) {
        gST->ConOut->OutputString(gST->ConOut, Str);
    }
}

static inline int AsciiStrCmp(const char *Str1, const char *Str2) {
    while (*Str1 && (*Str1 == *Str2)) {
        Str1++;
        Str2++;
    }
    return *(const unsigned char*)Str1 - *(const unsigned char*)Str2;
}

#endif // UEFI_MINIMAL_H
