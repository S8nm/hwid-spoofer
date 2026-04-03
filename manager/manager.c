/*
 * HWID SPOOFER - GUI Manager
 * 
 * Features:
 * - Dark themed Win32 GUI
 * - Shows original and current hardware IDs
 * - Change HWID with random generation each time
 * - Duration: 1 Day, 7 Days, 30 Days, Until Reboot
 * - Revert button to restore originals
 * - Driver files embedded as resources (single exe, no downloads)
 */

#include <windows.h>
#include <winternl.h>
#include <psapi.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <iphlpapi.h>
#include <shlobj.h>
#include <commctrl.h>

#include "resource.h"

#pragma comment(lib, "iphlpapi.lib")
#pragma comment(lib, "advapi32.lib")
#pragma comment(lib, "shell32.lib")
#pragma comment(lib, "comctl32.lib")
#pragma comment(lib, "gdi32.lib")
#pragma comment(lib, "user32.lib")
#pragma comment(lib, "ntdll.lib")
#pragma comment(lib, "psapi.lib")

#pragma comment(linker,"\"/manifestdependency:type='win32' \
name='Microsoft.Windows.Common-Controls' version='6.0.0.0' \
processorArchitecture='*' publicKeyToken='6595b64144ccf1df' language='*'\"")

// ==================== KDMAPPER CONFIGURATION ====================

#define IOCTL_NAL_MAP      0x80862007

// ==================== COLORS ====================

#define CLR_BG          RGB(18, 18, 30)
#define CLR_PANEL       RGB(26, 26, 46)
#define CLR_BORDER      RGB(50, 50, 80)
#define CLR_TEXT         RGB(200, 200, 220)
#define CLR_TEXT_DIM     RGB(120, 120, 150)
#define CLR_ACCENT       RGB(99, 102, 241)
#define CLR_GREEN        RGB(34, 197, 94)
#define CLR_RED          RGB(239, 68, 68)
#define CLR_ORANGE       RGB(249, 115, 22)
#define CLR_BTN_CHANGE   RGB(79, 70, 229)
#define CLR_BTN_REVERT   RGB(220, 38, 38)
#define CLR_BTN_HOVER_C  RGB(99, 90, 249)
#define CLR_BTN_HOVER_R  RGB(248, 58, 58)
#define CLR_WHITE        RGB(255, 255, 255)

// ==================== CONTROL IDS ====================

#define IDC_BTN_CHANGE      1001
#define IDC_BTN_REVERT      1002
#define IDC_COMBO_DURATION   1003
#define IDC_BTN_REFRESH      1004
#define IDT_DURATION_TIMER   2001
#define IDT_COUNTDOWN_TIMER  2002

// ==================== DURATION OPTIONS ====================

#define DUR_1_DAY       0
#define DUR_7_DAYS      1
#define DUR_30_DAYS     2
#define DUR_UNTIL_REBOOT 3

// ==================== GLOBALS ====================

static HINSTANCE g_hInst;
static HWND g_hWnd;
static HWND g_hBtnChange, g_hBtnRevert, g_hComboDuration, g_hBtnRefresh;
static HFONT g_hFontTitle, g_hFontNormal, g_hFontSmall, g_hFontBold, g_hFontMono;
static HBRUSH g_hBrBg, g_hBrPanel, g_hBrBorder;

static BOOL g_SpooferLoaded = FALSE;
static CHAR g_OriginalDiskSerial[256] = "(unknown)";
static UCHAR g_OriginalMAC[6] = {0};
static BOOL g_OriginalMACValid = FALSE;
static CHAR g_CurrentDiskSerial[256] = "(unknown)";
static UCHAR g_CurrentMAC[6] = {0};
static BOOL g_CurrentMACValid = FALSE;

static CHAR g_OrigBIOSSerial[256] = "(unknown)";
static CHAR g_OrigBoardSerial[256] = "(unknown)";
static CHAR g_OrigSystemUUID[256] = "(unknown)";
static ULONG g_OrigVolumeSerial = 0;
static BOOL g_OrigVolumeSerialValid = FALSE;
static CHAR g_OrigGPUID[256] = "(unknown)";

static CHAR g_CurrBIOSSerial[256] = "(unknown)";
static CHAR g_CurrBoardSerial[256] = "(unknown)";
static CHAR g_CurrSystemUUID[256] = "(unknown)";
static ULONG g_CurrVolumeSerial = 0;
static BOOL g_CurrVolumeSerialValid = FALSE;
static CHAR g_CurrGPUID[256] = "(unknown)";

static CHAR g_StatusText[256] = "INACTIVE";
static COLORREF g_StatusColor = CLR_RED;

// Extended ID tracking (from driver log)
#pragma pack(push, 1)
typedef struct {
    CHAR Magic[8];
    CHAR OrigDiskSerial[64];
    CHAR FakeDiskSerial[64];
    CHAR OrigBIOSSerial[64];
    CHAR FakeBIOSSerial[64];
    CHAR OrigBoardSerial[64];
    CHAR FakeBoardSerial[64];
    CHAR OrigSystemUUID[48];
    CHAR FakeSystemUUID[48];
    UCHAR OrigMAC[6];
    UCHAR FakeMAC[6];
    ULONG OrigVolumeSerial[1];
    ULONG FakeVolumeSerial[1];
    CHAR OrigGPUId[64];
    CHAR FakeGPUId[64];
    CHAR OrigModelNumber[48];
    CHAR FakeModelNumber[48];
    CHAR OrigFirmwareRev[16];
    CHAR FakeFirmwareRev[16];
} HWID_LOG;
#pragma pack(pop)

static HWID_LOG g_HwidLog = {0};
static BOOL g_LogLoaded = FALSE;

static CHAR g_TempDir[MAX_PATH] = {0};
static CHAR g_VulnDriverPath[MAX_PATH] = {0};
static CHAR g_VulnServiceName[32] = {0};
static CHAR g_VulnDeviceName[64] = {0};

// ==================== KDMAPPER STRUCTURES ====================

typedef struct {
    ULONG64 case_number;
    ULONG64 reserved;
    ULONG64 return_ptr;
    ULONG64 return_size;
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
    ULONG64 virt_addr;
    ULONG64 unused1;
    ULONG64 phys_addr;
    ULONG64 size;
} UNMAP_IO_SPACE_BUFFER;

typedef NTSTATUS(NTAPI* pNtQuerySystemInformation)(
    ULONG SystemInformationClass,
    PVOID SystemInformation,
    ULONG SystemInformationLength,
    PULONG ReturnLength
);

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

static HANDLE g_hVulnDriver = INVALID_HANDLE_VALUE;
static PVOID g_KernelBase = NULL;

typedef NTSTATUS(NTAPI* pNtQueryIntervalProfile)(ULONG ProfileSource, PULONG Interval);

static ULONGLONG g_SpoofExpiry = 0;   // 0 = no expiry (until reboot)
static int g_SelectedDuration = DUR_UNTIL_REBOOT;
static CHAR g_TimeRemaining[64] = "";

static BOOL g_HoverChange = FALSE;
static BOOL g_HoverRevert = FALSE;

// ==================== PROTOTYPES ====================

LRESULT CALLBACK WndProc(HWND, UINT, WPARAM, LPARAM);
void InitFonts();
void DestroyFonts();
void ReadAllHWIDs();
BOOL GetDiskSerial(char* buffer, size_t bufferSize);
BOOL GetMACAddress(UCHAR* mac);
BOOL GetBIOSSerial(char* buffer, size_t bufferSize);
BOOL GetBoardSerial(char* buffer, size_t bufferSize);
BOOL GetSystemUUID(char* buffer, size_t bufferSize);
BOOL GetVolumeSerialNum(ULONG* serial);
BOOL GetGPUID(char* buffer, size_t bufferSize);
void GenerateRandomSerial(char* buffer, size_t bufferSize);
void GenerateRandomMAC(UCHAR* mac);
void DoSpoofHWID();
void DoRevertHWID();
void UpdateStatus();
void RefreshCurrentHWIDs();
BOOL CreateHiddenTempDirectory();
BOOL ExtractResource(int resourceId, const char* outputPath);
BOOL ExtractDriverFiles();
void SecureWipeFile(const char* path);
void CleanupTempFiles();
void GenerateRandomHexName(char* buffer, size_t len);
BOOL LoadSpooferDriver();
BOOL UnloadSpooferDriver();
BOOL IsAdmin();
BOOL ReadHwidLog();
void SaveHwidLogToDocuments();

// Kdmapper integrated functions
BOOL LoadVulnerableDriver();
VOID UnloadVulnerableDriver();
PVOID KM_GetKernelBase();
PVOID KM_MapPhysicalMemory(ULONG64 physAddr, SIZE_T size);
VOID KM_UnmapPhysicalMemory(PVOID virtAddr, SIZE_T size);
BOOL KM_CopyKernelMemory(ULONG64 dest, ULONG64 src, SIZE_T size);
BOOL KM_ReadKernelMemory(ULONG64 kernelAddr, PVOID buffer, SIZE_T size);
BOOL KM_WriteKernelMemory(ULONG64 kernelAddr, PVOID buffer, SIZE_T size);
PVOID KM_GetKernelExport(const char* name);
BOOL KM_ProcessRelocations(PVOID imageBase, PVOID mappedBase, SIZE_T imageSize);
BOOL KM_ResolveImports(PVOID imageBase);
ULONG64 KM_FindCodeCave(SIZE_T needed);
BOOL KM_ExecuteInKernel(ULONG64 funcAddr);
ULONG64 KM_AllocateKernelPool(SIZE_T size);
BOOL KM_CallDriverEntry(ULONG64 entryAddr);
BOOL KM_MapDriverFromMemory(PVOID buffer, DWORD size);
void DrawPanel(HDC hdc, RECT* rc, const char* title);
void DrawTextLine(HDC hdc, int x, int y, const char* label, const char* value, COLORREF valColor);

// ==================== ENTRY POINT ====================

int WINAPI WinMain(HINSTANCE hInstance, HINSTANCE hPrev, LPSTR lpCmd, int nShow) {
    (void)hPrev; (void)lpCmd;
    g_hInst = hInstance;

    if (!IsAdmin()) {
        MessageBoxA(NULL,
            "Administrator privileges required!\n\nRight-click and select 'Run as Administrator'.",
            "HWID Spoofer", MB_ICONERROR | MB_OK);
        return 1;
    }

    srand((unsigned int)time(NULL) ^ GetTickCount());

    INITCOMMONCONTROLSEX icc = { sizeof(icc), ICC_STANDARD_CLASSES };
    InitCommonControlsEx(&icc);

    WNDCLASSEXA wc = {0};
    wc.cbSize        = sizeof(wc);
    wc.style         = CS_HREDRAW | CS_VREDRAW;
    wc.lpfnWndProc   = WndProc;
    wc.hInstance      = hInstance;
    wc.hCursor        = LoadCursor(NULL, IDC_ARROW);
    wc.hbrBackground  = NULL;
    wc.lpszClassName  = "HWIDSpooferWnd";
    wc.hIcon          = LoadIcon(NULL, IDI_SHIELD);
    wc.hIconSm        = LoadIcon(NULL, IDI_SHIELD);
    RegisterClassExA(&wc);

    int wndW = 540, wndH = 940;
    int scrW = GetSystemMetrics(SM_CXSCREEN);
    int scrH = GetSystemMetrics(SM_CYSCREEN);

    g_hWnd = CreateWindowExA(
        0, "HWIDSpooferWnd", "HWID Spoofer",
        WS_OVERLAPPED | WS_CAPTION | WS_SYSMENU | WS_MINIMIZEBOX,
        (scrW - wndW) / 2, (scrH - wndH) / 2, wndW, wndH,
        NULL, NULL, hInstance, NULL);

    ShowWindow(g_hWnd, nShow);
    UpdateWindow(g_hWnd);

    MSG msg;
    while (GetMessage(&msg, NULL, 0, 0)) {
        TranslateMessage(&msg);
        DispatchMessage(&msg);
    }

    return (int)msg.wParam;
}

// ==================== FONTS ====================

void InitFonts() {
    g_hFontTitle  = CreateFontA(22, 0, 0, 0, FW_BOLD, 0, 0, 0,
        DEFAULT_CHARSET, 0, 0, CLEARTYPE_QUALITY, 0, "Segoe UI");
    g_hFontNormal = CreateFontA(15, 0, 0, 0, FW_NORMAL, 0, 0, 0,
        DEFAULT_CHARSET, 0, 0, CLEARTYPE_QUALITY, 0, "Segoe UI");
    g_hFontSmall  = CreateFontA(13, 0, 0, 0, FW_NORMAL, 0, 0, 0,
        DEFAULT_CHARSET, 0, 0, CLEARTYPE_QUALITY, 0, "Segoe UI");
    g_hFontBold   = CreateFontA(15, 0, 0, 0, FW_SEMIBOLD, 0, 0, 0,
        DEFAULT_CHARSET, 0, 0, CLEARTYPE_QUALITY, 0, "Segoe UI");
    g_hFontMono   = CreateFontA(14, 0, 0, 0, FW_NORMAL, 0, 0, 0,
        DEFAULT_CHARSET, 0, 0, CLEARTYPE_QUALITY, 0, "Consolas");
}

void DestroyFonts() {
    DeleteObject(g_hFontTitle);
    DeleteObject(g_hFontNormal);
    DeleteObject(g_hFontSmall);
    DeleteObject(g_hFontBold);
    DeleteObject(g_hFontMono);
}

// ==================== DRAWING HELPERS ====================

void DrawPanel(HDC hdc, RECT* rc, const char* title) {
    HBRUSH br = CreateSolidBrush(CLR_PANEL);
    HPEN pen = CreatePen(PS_SOLID, 1, CLR_BORDER);
    SelectObject(hdc, br);
    SelectObject(hdc, pen);
    RoundRect(hdc, rc->left, rc->top, rc->right, rc->bottom, 10, 10);
    DeleteObject(br);
    DeleteObject(pen);

    if (title) {
        SelectObject(hdc, g_hFontBold);
        SetTextColor(hdc, CLR_ACCENT);
        SetBkMode(hdc, TRANSPARENT);
        TextOutA(hdc, rc->left + 14, rc->top + 10, title, (int)strlen(title));
    }
}

void DrawTextLine(HDC hdc, int x, int y, const char* label, const char* value, COLORREF valColor) {
    SetBkMode(hdc, TRANSPARENT);

    SelectObject(hdc, g_hFontNormal);
    SetTextColor(hdc, CLR_TEXT_DIM);
    TextOutA(hdc, x, y, label, (int)strlen(label));

    SelectObject(hdc, g_hFontMono);
    SetTextColor(hdc, valColor);
    TextOutA(hdc, x + 120, y, value, (int)strlen(value));
}

void DrawButton(HDC hdc, RECT* rc, const char* text, COLORREF bgColor, BOOL hover) {
    COLORREF col = hover ? (bgColor == CLR_BTN_CHANGE ? CLR_BTN_HOVER_C : CLR_BTN_HOVER_R) : bgColor;
    HBRUSH br = CreateSolidBrush(col);
    HPEN pen = CreatePen(PS_SOLID, 1, col);
    SelectObject(hdc, br);
    SelectObject(hdc, pen);
    RoundRect(hdc, rc->left, rc->top, rc->right, rc->bottom, 8, 8);
    DeleteObject(br);
    DeleteObject(pen);

    SetBkMode(hdc, TRANSPARENT);
    SetTextColor(hdc, CLR_WHITE);
    SelectObject(hdc, g_hFontBold);
    DrawTextA(hdc, text, -1, rc, DT_CENTER | DT_VCENTER | DT_SINGLELINE);
}

// ==================== WINDOW PROC ====================

LRESULT CALLBACK WndProc(HWND hWnd, UINT msg, WPARAM wParam, LPARAM lParam) {
    switch (msg) {

    case WM_CREATE: {
        g_hBrBg    = CreateSolidBrush(CLR_BG);
        g_hBrPanel = CreateSolidBrush(CLR_PANEL);
        g_hBrBorder = CreateSolidBrush(CLR_BORDER);
        InitFonts();

        // Duration combo
        g_hComboDuration = CreateWindowExA(0, "COMBOBOX", NULL,
            WS_CHILD | WS_VISIBLE | CBS_DROPDOWNLIST | CBS_HASSTRINGS,
            290, 728, 190, 200, hWnd, (HMENU)IDC_COMBO_DURATION, g_hInst, NULL);
        SendMessageA(g_hComboDuration, CB_ADDSTRING, 0, (LPARAM)"1 Day");
        SendMessageA(g_hComboDuration, CB_ADDSTRING, 0, (LPARAM)"7 Days");
        SendMessageA(g_hComboDuration, CB_ADDSTRING, 0, (LPARAM)"30 Days");
        SendMessageA(g_hComboDuration, CB_ADDSTRING, 0, (LPARAM)"Until Reboot");
        SendMessageA(g_hComboDuration, CB_SETCURSEL, DUR_UNTIL_REBOOT, 0);
        SendMessageA(g_hComboDuration, WM_SETFONT, (WPARAM)g_hFontNormal, TRUE);

        // Read HWIDs on startup
        ReadAllHWIDs();
        strcpy_s(g_CurrentDiskSerial, sizeof(g_CurrentDiskSerial), g_OriginalDiskSerial);
        memcpy(g_CurrentMAC, g_OriginalMAC, 6);
        g_CurrentMACValid = g_OriginalMACValid;
        strcpy_s(g_CurrBIOSSerial, sizeof(g_CurrBIOSSerial), g_OrigBIOSSerial);
        strcpy_s(g_CurrBoardSerial, sizeof(g_CurrBoardSerial), g_OrigBoardSerial);
        strcpy_s(g_CurrSystemUUID, sizeof(g_CurrSystemUUID), g_OrigSystemUUID);
        g_CurrVolumeSerial = g_OrigVolumeSerial;
        g_CurrVolumeSerialValid = g_OrigVolumeSerialValid;
        strcpy_s(g_CurrGPUID, sizeof(g_CurrGPUID), g_OrigGPUID);

        if (!CreateHiddenTempDirectory()) {
            MessageBoxA(hWnd, "Failed to create temp directory.", "Error", MB_ICONERROR);
        }

        // Countdown timer (1 second)
        SetTimer(hWnd, IDT_COUNTDOWN_TIMER, 1000, NULL);
        return 0;
    }

    case WM_TIMER: {
        if (wParam == IDT_DURATION_TIMER) {
            // Duration expired - auto revert
            KillTimer(hWnd, IDT_DURATION_TIMER);
            g_SpoofExpiry = 0;
            DoRevertHWID();
            InvalidateRect(hWnd, NULL, TRUE);
        }
        else if (wParam == IDT_COUNTDOWN_TIMER) {
            if (g_SpooferLoaded && g_SpoofExpiry > 0) {
                ULONGLONG now = GetTickCount64();
                if (now >= g_SpoofExpiry) {
                    strcpy_s(g_TimeRemaining, sizeof(g_TimeRemaining), "Expiring...");
                } else {
                    ULONGLONG remaining = (g_SpoofExpiry - now) / 1000;
                    int days = (int)(remaining / 86400);
                    int hours = (int)((remaining % 86400) / 3600);
                    int mins = (int)((remaining % 3600) / 60);
                    int secs = (int)(remaining % 60);
                    if (days > 0)
                        sprintf_s(g_TimeRemaining, sizeof(g_TimeRemaining),
                                  "%dd %02dh %02dm %02ds", days, hours, mins, secs);
                    else
                        sprintf_s(g_TimeRemaining, sizeof(g_TimeRemaining),
                                  "%02dh %02dm %02ds", hours, mins, secs);
                }
                InvalidateRect(hWnd, NULL, FALSE);
            }
        }
        return 0;
    }

    case WM_PAINT: {
        PAINTSTRUCT ps;
        HDC hdc = BeginPaint(hWnd, &ps);

        RECT clientRect;
        GetClientRect(hWnd, &clientRect);

        // Double buffer
        HDC memDC = CreateCompatibleDC(hdc);
        HBITMAP memBmp = CreateCompatibleBitmap(hdc, clientRect.right, clientRect.bottom);
        SelectObject(memDC, memBmp);

        // Background
        FillRect(memDC, &clientRect, g_hBrBg);

        // Title
        SetBkMode(memDC, TRANSPARENT);
        SelectObject(memDC, g_hFontTitle);
        SetTextColor(memDC, CLR_WHITE);
        TextOutA(memDC, 20, 16, "HWID Spoofer", 12);

        // Status badge
        SelectObject(memDC, g_hFontBold);
        SetTextColor(memDC, g_StatusColor);
        {
            char statusBuf[300];
            sprintf_s(statusBuf, sizeof(statusBuf), "[%s]", g_StatusText);
            SIZE sz;
            GetTextExtentPoint32A(memDC, statusBuf, (int)strlen(statusBuf), &sz);
            TextOutA(memDC, clientRect.right - sz.cx - 20, 20, statusBuf, (int)strlen(statusBuf));
        }

        // === Panel 1: Original HWIDs (saved at startup, never changes) ===
        RECT panelOrig = {20, 55, clientRect.right - 20, 225};
        DrawPanel(memDC, &panelOrig, "ORIGINAL HARDWARE IDs");
        {
            int y = panelOrig.top + 32;
            char macStr[32];
            DrawTextLine(memDC, 34, y, "Disk Serial:", g_OriginalDiskSerial, CLR_TEXT); y += 19;
            if (g_OriginalMACValid)
                sprintf_s(macStr, sizeof(macStr), "%02X:%02X:%02X:%02X:%02X:%02X",
                    g_OriginalMAC[0], g_OriginalMAC[1], g_OriginalMAC[2],
                    g_OriginalMAC[3], g_OriginalMAC[4], g_OriginalMAC[5]);
            else strcpy_s(macStr, sizeof(macStr), "(unknown)");
            DrawTextLine(memDC, 34, y, "MAC Address:", macStr, CLR_TEXT); y += 19;
            DrawTextLine(memDC, 34, y, "BIOS Serial:", g_OrigBIOSSerial, CLR_TEXT); y += 19;
            DrawTextLine(memDC, 34, y, "Board Serial:", g_OrigBoardSerial, CLR_TEXT); y += 19;
            DrawTextLine(memDC, 34, y, "System UUID:", g_OrigSystemUUID, CLR_TEXT); y += 19;
            { char vb[32];
              if (g_OrigVolumeSerialValid) sprintf_s(vb, sizeof(vb), "%08X", g_OrigVolumeSerial);
              else strcpy_s(vb, sizeof(vb), "(not available)");
              DrawTextLine(memDC, 34, y, "Volume Serial:", vb, CLR_TEXT); } y += 19;
            DrawTextLine(memDC, 34, y, "GPU ID:", g_OrigGPUID, CLR_TEXT);
        }

        // === Panel 2: Current HWIDs (live detection — reflects spoof when active) ===
        RECT panelCurr = {20, 233, clientRect.right - 20, 403};
        DrawPanel(memDC, &panelCurr, "CURRENT HARDWARE IDs");
        {
            int y = panelCurr.top + 32;
            char macStr[32];
            COLORREF cDisk = (g_SpooferLoaded && strcmp(g_OriginalDiskSerial, g_CurrentDiskSerial) != 0) ? CLR_GREEN : CLR_TEXT;
            DrawTextLine(memDC, 34, y, "Disk Serial:", g_CurrentDiskSerial, cDisk); y += 19;

            if (g_CurrentMACValid)
                sprintf_s(macStr, sizeof(macStr), "%02X:%02X:%02X:%02X:%02X:%02X",
                    g_CurrentMAC[0], g_CurrentMAC[1], g_CurrentMAC[2],
                    g_CurrentMAC[3], g_CurrentMAC[4], g_CurrentMAC[5]);
            else strcpy_s(macStr, sizeof(macStr), "(unknown)");
            COLORREF cMac = (g_SpooferLoaded && g_CurrentMACValid && g_OriginalMACValid &&
                memcmp(g_OriginalMAC, g_CurrentMAC, 6) != 0) ? CLR_GREEN : CLR_TEXT;
            DrawTextLine(memDC, 34, y, "MAC Address:", macStr, cMac); y += 19;

            COLORREF cBios = (g_SpooferLoaded && strcmp(g_OrigBIOSSerial, g_CurrBIOSSerial) != 0) ? CLR_GREEN : CLR_TEXT;
            DrawTextLine(memDC, 34, y, "BIOS Serial:", g_CurrBIOSSerial, cBios); y += 19;
            COLORREF cBoard = (g_SpooferLoaded && strcmp(g_OrigBoardSerial, g_CurrBoardSerial) != 0) ? CLR_GREEN : CLR_TEXT;
            DrawTextLine(memDC, 34, y, "Board Serial:", g_CurrBoardSerial, cBoard); y += 19;
            COLORREF cUuid = (g_SpooferLoaded && strcmp(g_OrigSystemUUID, g_CurrSystemUUID) != 0) ? CLR_GREEN : CLR_TEXT;
            DrawTextLine(memDC, 34, y, "System UUID:", g_CurrSystemUUID, cUuid); y += 19;
            { char vb[32];
              if (g_CurrVolumeSerialValid) sprintf_s(vb, sizeof(vb), "%08X", g_CurrVolumeSerial);
              else strcpy_s(vb, sizeof(vb), "(not available)");
              COLORREF cVol = (g_SpooferLoaded && g_CurrVolumeSerial != g_OrigVolumeSerial) ? CLR_GREEN : CLR_TEXT;
              DrawTextLine(memDC, 34, y, "Volume Serial:", vb, cVol); } y += 19;
            COLORREF cGpu = (g_SpooferLoaded && strcmp(g_OrigGPUID, g_CurrGPUID) != 0) ? CLR_GREEN : CLR_TEXT;
            DrawTextLine(memDC, 34, y, "GPU ID:", g_CurrGPUID, cGpu);
        }

        // === Panel 3: Spoofed To (fake values from driver log) ===
        RECT panelSpoof = {20, 411, clientRect.right - 20, 581};
        DrawPanel(memDC, &panelSpoof, "SPOOFED TO");
        {
            int y = panelSpoof.top + 32;
            if (g_LogLoaded) {
                char macStr[32];
                DrawTextLine(memDC, 34, y, "Disk Serial:", g_HwidLog.FakeDiskSerial, CLR_GREEN); y += 19;
                sprintf_s(macStr, sizeof(macStr), "%02X:%02X:%02X:%02X:%02X:%02X",
                    g_HwidLog.FakeMAC[0], g_HwidLog.FakeMAC[1], g_HwidLog.FakeMAC[2],
                    g_HwidLog.FakeMAC[3], g_HwidLog.FakeMAC[4], g_HwidLog.FakeMAC[5]);
                DrawTextLine(memDC, 34, y, "MAC Address:", macStr, CLR_GREEN); y += 19;
                DrawTextLine(memDC, 34, y, "BIOS Serial:", g_HwidLog.FakeBIOSSerial, CLR_GREEN); y += 19;
                DrawTextLine(memDC, 34, y, "Board Serial:", g_HwidLog.FakeBoardSerial, CLR_GREEN); y += 19;
                DrawTextLine(memDC, 34, y, "System UUID:", g_HwidLog.FakeSystemUUID, CLR_GREEN); y += 19;
                { char vb[32]; sprintf_s(vb, sizeof(vb), "%08X", g_HwidLog.FakeVolumeSerial[0]);
                  DrawTextLine(memDC, 34, y, "Volume Serial:", vb, CLR_GREEN); } y += 19;
                DrawTextLine(memDC, 34, y, "GPU ID:", g_HwidLog.FakeGPUId, CLR_GREEN);
            } else {
                DrawTextLine(memDC, 34, y, "Disk Serial:", "(not yet spoofed)", CLR_TEXT_DIM); y += 19;
                DrawTextLine(memDC, 34, y, "MAC Address:", "(not yet spoofed)", CLR_TEXT_DIM); y += 19;
                DrawTextLine(memDC, 34, y, "BIOS Serial:", "(not yet spoofed)", CLR_TEXT_DIM); y += 19;
                DrawTextLine(memDC, 34, y, "Board Serial:", "(not yet spoofed)", CLR_TEXT_DIM); y += 19;
                DrawTextLine(memDC, 34, y, "System UUID:", "(not yet spoofed)", CLR_TEXT_DIM); y += 19;
                DrawTextLine(memDC, 34, y, "Volume Serial:", "(not yet spoofed)", CLR_TEXT_DIM); y += 19;
                DrawTextLine(memDC, 34, y, "GPU ID:", "(not yet spoofed)", CLR_TEXT_DIM);
            }
        }

        // === Spoof Status Panel ===
        RECT panelInfo = {20, 589, clientRect.right - 20, 706};
        DrawPanel(memDC, &panelInfo, "SPOOF STATUS");
        {
            int y = panelInfo.top + 32;
            if (g_SpooferLoaded) {
                SetTextColor(memDC, CLR_GREEN);
                SelectObject(memDC, g_hFontBold);
                TextOutA(memDC, 34, y, "Spoofer is ACTIVE", 17); y += 24;
                SelectObject(memDC, g_hFontNormal);
                SetTextColor(memDC, CLR_TEXT_DIM);
                const char* durNames[] = {"1 Day", "7 Days", "30 Days", "Until Reboot"};
                char durBuf[128];
                sprintf_s(durBuf, sizeof(durBuf), "Duration: %s", durNames[g_SelectedDuration]);
                TextOutA(memDC, 34, y, durBuf, (int)strlen(durBuf)); y += 20;
                if (g_SpoofExpiry > 0) {
                    char timeBuf[128];
                    sprintf_s(timeBuf, sizeof(timeBuf), "Time Remaining: %s", g_TimeRemaining);
                    SetTextColor(memDC, CLR_ORANGE);
                    TextOutA(memDC, 34, y, timeBuf, (int)strlen(timeBuf));
                } else {
                    TextOutA(memDC, 34, y, "Active until reboot or manual revert", 36);
                }
            } else {
                SetTextColor(memDC, CLR_RED);
                SelectObject(memDC, g_hFontBold);
                TextOutA(memDC, 34, y, "Spoofer is INACTIVE", 19); y += 24;
                SetTextColor(memDC, CLR_TEXT_DIM);
                SelectObject(memDC, g_hFontNormal);
                TextOutA(memDC, 34, y, "Select a duration and click 'Change HWID' to start.", 52); y += 20;
                SelectObject(memDC, g_hFontSmall);
                TextOutA(memDC, 34, y, "Disk, MAC, BIOS, Board, UUID, Volume, GPU will be randomized", 60);
            }
        }

        // === Bottom Controls ===
        SelectObject(memDC, g_hFontNormal);
        SetTextColor(memDC, CLR_TEXT_DIM);
        SetBkMode(memDC, TRANSPARENT);
        TextOutA(memDC, 290, 712, "Duration:", 9);

        RECT rcChange = {20, 730, 265, 765};
        DrawButton(memDC, &rcChange, g_SpooferLoaded ? "Randomize Again" : "Change HWID",
                   CLR_BTN_CHANGE, g_HoverChange);

        RECT rcRevert = {20, 775, 265, 808};
        DrawButton(memDC, &rcRevert, "Revert to Original", CLR_BTN_REVERT, g_HoverRevert);

        {
            RECT rcRefresh = {290, 775, 490, 808};
            HBRUSH brRef = CreateSolidBrush(CLR_PANEL);
            HPEN penRef = CreatePen(PS_SOLID, 1, CLR_BORDER);
            SelectObject(memDC, brRef);
            SelectObject(memDC, penRef);
            RoundRect(memDC, rcRefresh.left, rcRefresh.top, rcRefresh.right, rcRefresh.bottom, 8, 8);
            DeleteObject(brRef);
            DeleteObject(penRef);
            SetTextColor(memDC, CLR_ACCENT);
            SelectObject(memDC, g_hFontNormal);
            DrawTextA(memDC, "Refresh HWIDs", -1, &rcRefresh, DT_CENTER | DT_VCENTER | DT_SINGLELINE);
        }

        // Blit
        BitBlt(hdc, 0, 0, clientRect.right, clientRect.bottom, memDC, 0, 0, SRCCOPY);
        DeleteObject(memBmp);
        DeleteDC(memDC);

        EndPaint(hWnd, &ps);
        return 0;
    }

    case WM_LBUTTONDOWN: {
        int mx = LOWORD(lParam);
        int my = HIWORD(lParam);

        if (mx >= 20 && mx <= 265 && my >= 730 && my <= 765) {
            DoSpoofHWID();
            InvalidateRect(hWnd, NULL, TRUE);
        }
        else if (mx >= 20 && mx <= 265 && my >= 775 && my <= 808) {
            DoRevertHWID();
            InvalidateRect(hWnd, NULL, TRUE);
        }
        else if (mx >= 290 && mx <= 490 && my >= 775 && my <= 808) {
            RefreshCurrentHWIDs();
            InvalidateRect(hWnd, NULL, TRUE);
        }
        return 0;
    }

    case WM_MOUSEMOVE: {
        int mx = LOWORD(lParam);
        int my = HIWORD(lParam);
        BOOL newHoverC = (mx >= 20 && mx <= 265 && my >= 730 && my <= 765);
        BOOL newHoverR = (mx >= 20 && mx <= 265 && my >= 775 && my <= 808);
        if (newHoverC != g_HoverChange || newHoverR != g_HoverRevert) {
            g_HoverChange = newHoverC;
            g_HoverRevert = newHoverR;
            InvalidateRect(hWnd, NULL, FALSE);
        }

        // Track mouse leave
        TRACKMOUSEEVENT tme = { sizeof(tme), TME_LEAVE, hWnd, 0 };
        TrackMouseEvent(&tme);
        return 0;
    }

    case WM_MOUSELEAVE: {
        if (g_HoverChange || g_HoverRevert) {
            g_HoverChange = FALSE;
            g_HoverRevert = FALSE;
            InvalidateRect(hWnd, NULL, FALSE);
        }
        return 0;
    }

    case WM_CTLCOLORLISTBOX:
    case WM_CTLCOLOREDIT: {
        HDC hdcCtl = (HDC)wParam;
        SetTextColor(hdcCtl, CLR_TEXT);
        SetBkColor(hdcCtl, CLR_PANEL);
        return (LRESULT)g_hBrPanel;
    }

    case WM_COMMAND: {
        if (LOWORD(wParam) == IDC_COMBO_DURATION && HIWORD(wParam) == CBN_SELCHANGE) {
            g_SelectedDuration = (int)SendMessageA(g_hComboDuration, CB_GETCURSEL, 0, 0);
        }
        return 0;
    }

    case WM_ERASEBKGND:
        return 1;

    case WM_DESTROY: {
        KillTimer(hWnd, IDT_DURATION_TIMER);
        KillTimer(hWnd, IDT_COUNTDOWN_TIMER);
        if (g_SpooferLoaded) {
            UnloadSpooferDriver();
        }
        CleanupTempFiles();
        DestroyFonts();
        DeleteObject(g_hBrBg);
        DeleteObject(g_hBrPanel);
        DeleteObject(g_hBrBorder);
        PostQuitMessage(0);
        return 0;
    }

    default:
        return DefWindowProcA(hWnd, msg, wParam, lParam);
    }
}

// ==================== HWID READING ====================

BOOL GetDiskSerial(char* buffer, size_t bufferSize) {
    typedef struct {
        DWORD PropertyId;
        DWORD QueryType;
        BYTE  AdditionalParameters[1];
    } STOR_PROP_QUERY;

    typedef struct {
        DWORD Version;
        DWORD Size;
        BYTE  DeviceType;
        BYTE  DeviceTypeModifier;
        BOOLEAN RemovableMedia;
        BOOLEAN CommandQueueing;
        DWORD VendorIdOffset;
        DWORD ProductIdOffset;
        DWORD ProductRevisionOffset;
        DWORD SerialNumberOffset;
        DWORD BusType;
        DWORD RawPropertiesLength;
        BYTE  RawDeviceProperties[1];
    } STOR_DEV_DESC;

    HANDLE hDevice = CreateFileA("\\\\.\\PhysicalDrive0", 0,
        FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, OPEN_EXISTING, 0, NULL);
    if (hDevice == INVALID_HANDLE_VALUE) return FALSE;

    STOR_PROP_QUERY query = {0};
    BYTE outBuf[1024] = {0};
    DWORD bytesReturned = 0;

    BOOL result = DeviceIoControl(hDevice, 0x002D1400,
        &query, sizeof(query), outBuf, sizeof(outBuf), &bytesReturned, NULL);
    CloseHandle(hDevice);

    if (!result || bytesReturned < sizeof(STOR_DEV_DESC)) return FALSE;

    STOR_DEV_DESC* desc = (STOR_DEV_DESC*)outBuf;
    if (desc->SerialNumberOffset > 0 && desc->SerialNumberOffset < bytesReturned) {
        char* serial = (char*)(outBuf + desc->SerialNumberOffset);
        while (*serial == ' ') serial++;
        size_t len = strlen(serial);
        while (len > 0 && serial[len - 1] == ' ') { serial[--len] = '\0'; }
        if (*serial) {
            strncpy_s(buffer, bufferSize, serial, _TRUNCATE);
            return TRUE;
        }
    }
    return FALSE;
}

BOOL GetMACAddress(UCHAR* mac) {
    PIP_ADAPTER_INFO adapterInfo = NULL;
    ULONG bufferSize = 0;

    GetAdaptersInfo(NULL, &bufferSize);
    if (bufferSize == 0) return FALSE;

    adapterInfo = (PIP_ADAPTER_INFO)malloc(bufferSize);
    if (!adapterInfo) return FALSE;

    BOOL found = FALSE;
    if (GetAdaptersInfo(adapterInfo, &bufferSize) == ERROR_SUCCESS) {
        PIP_ADAPTER_INFO adapter = adapterInfo;
        while (adapter) {
            if (adapter->Type == MIB_IF_TYPE_ETHERNET ||
                adapter->Type == IF_TYPE_IEEE80211) {
                memcpy(mac, adapter->Address, 6);
                found = TRUE;
                break;
            }
            adapter = adapter->Next;
        }
    }
    free(adapterInfo);
    return found;
}

BOOL GetBIOSSerial(char* buffer, size_t bufferSize) {
    HKEY hKey;
    if (RegOpenKeyExA(HKEY_LOCAL_MACHINE,
            "HARDWARE\\DESCRIPTION\\System\\BIOS", 0, KEY_READ, &hKey) != ERROR_SUCCESS)
        return FALSE;
    DWORD size = (DWORD)bufferSize;
    DWORD type = 0;
    LSTATUS res = RegQueryValueExA(hKey, "SystemSerialNumber", NULL, &type, (LPBYTE)buffer, &size);
    RegCloseKey(hKey);
    return (res == ERROR_SUCCESS && type == REG_SZ && buffer[0] != '\0');
}

BOOL GetBoardSerial(char* buffer, size_t bufferSize) {
    HKEY hKey;
    if (RegOpenKeyExA(HKEY_LOCAL_MACHINE,
            "HARDWARE\\DESCRIPTION\\System\\BIOS", 0, KEY_READ, &hKey) != ERROR_SUCCESS)
        return FALSE;
    DWORD size = (DWORD)bufferSize;
    DWORD type = 0;
    LSTATUS res = RegQueryValueExA(hKey, "BaseBoardSerialNumber", NULL, &type, (LPBYTE)buffer, &size);
    RegCloseKey(hKey);
    return (res == ERROR_SUCCESS && type == REG_SZ && buffer[0] != '\0');
}

BOOL GetSystemUUID(char* buffer, size_t bufferSize) {
    typedef struct {
        BYTE  Used20CallingMethod;
        BYTE  SMBIOSMajorVersion;
        BYTE  SMBIOSMinorVersion;
        BYTE  DmiRevision;
        DWORD Length;
    } RAW_SMBIOS_HDR;

    DWORD size = GetSystemFirmwareTable('RSMB', 0, NULL, 0);
    if (size == 0) return FALSE;

    BYTE* data = (BYTE*)malloc(size);
    if (!data) return FALSE;

    if (GetSystemFirmwareTable('RSMB', 0, data, size) != size) {
        free(data);
        return FALSE;
    }

    RAW_SMBIOS_HDR* hdr = (RAW_SMBIOS_HDR*)data;
    BYTE* tbl = data + sizeof(RAW_SMBIOS_HDR);
    BYTE* tblEnd = tbl + hdr->Length;
    BYTE* ptr = tbl;

    while (ptr + 4 < tblEnd) {
        BYTE type = ptr[0];
        BYTE length = ptr[1];
        if (length < 4) break;

        if (type == 1 && length >= 0x19) {
            BYTE* uuid = ptr + 0x08;
            sprintf_s(buffer, bufferSize,
                "%02X%02X%02X%02X-%02X%02X-%02X%02X-%02X%02X-%02X%02X%02X%02X%02X%02X",
                uuid[3], uuid[2], uuid[1], uuid[0],
                uuid[5], uuid[4],
                uuid[7], uuid[6],
                uuid[8], uuid[9],
                uuid[10], uuid[11], uuid[12], uuid[13], uuid[14], uuid[15]);
            free(data);
            return TRUE;
        }

        ptr += length;
        while (ptr < tblEnd - 1 && !(ptr[0] == 0 && ptr[1] == 0)) ptr++;
        ptr += 2;
    }

    free(data);
    return FALSE;
}

BOOL GetVolumeSerialNum(ULONG* serial) {
    DWORD volSerial = 0;
    if (GetVolumeInformationA("C:\\", NULL, 0, &volSerial, NULL, NULL, NULL, 0)) {
        *serial = volSerial;
        return TRUE;
    }
    return FALSE;
}

BOOL GetGPUID(char* buffer, size_t bufferSize) {
    HKEY hKey;
    if (RegOpenKeyExA(HKEY_LOCAL_MACHINE,
            "SYSTEM\\CurrentControlSet\\Control\\Class\\"
            "{4d36e968-e325-11ce-bfc1-08002be10318}\\0000",
            0, KEY_READ, &hKey) != ERROR_SUCCESS)
        return FALSE;
    DWORD size = (DWORD)bufferSize;
    DWORD type = 0;
    LSTATUS res = RegQueryValueExA(hKey, "HardwareInformation.AdapterString",
        NULL, &type, (LPBYTE)buffer, &size);
    if (res == ERROR_SUCCESS && buffer[0] != '\0') {
        RegCloseKey(hKey);
        return TRUE;
    }
    size = (DWORD)bufferSize;
    res = RegQueryValueExA(hKey, "DriverDesc", NULL, &type, (LPBYTE)buffer, &size);
    RegCloseKey(hKey);
    return (res == ERROR_SUCCESS && buffer[0] != '\0');
}

void ReadAllHWIDs() {
    if (!GetDiskSerial(g_OriginalDiskSerial, sizeof(g_OriginalDiskSerial)))
        strcpy_s(g_OriginalDiskSerial, sizeof(g_OriginalDiskSerial), "(failed to read)");
    g_OriginalMACValid = GetMACAddress(g_OriginalMAC);
    if (!GetBIOSSerial(g_OrigBIOSSerial, sizeof(g_OrigBIOSSerial)))
        strcpy_s(g_OrigBIOSSerial, sizeof(g_OrigBIOSSerial), "(not available)");
    if (!GetBoardSerial(g_OrigBoardSerial, sizeof(g_OrigBoardSerial)))
        strcpy_s(g_OrigBoardSerial, sizeof(g_OrigBoardSerial), "(not available)");
    if (!GetSystemUUID(g_OrigSystemUUID, sizeof(g_OrigSystemUUID)))
        strcpy_s(g_OrigSystemUUID, sizeof(g_OrigSystemUUID), "(not available)");
    g_OrigVolumeSerialValid = GetVolumeSerialNum(&g_OrigVolumeSerial);
    if (!GetGPUID(g_OrigGPUID, sizeof(g_OrigGPUID)))
        strcpy_s(g_OrigGPUID, sizeof(g_OrigGPUID), "(not available)");
}

void RefreshCurrentHWIDs() {
    if (!GetDiskSerial(g_CurrentDiskSerial, sizeof(g_CurrentDiskSerial)))
        strcpy_s(g_CurrentDiskSerial, sizeof(g_CurrentDiskSerial), "(failed to read)");
    g_CurrentMACValid = GetMACAddress(g_CurrentMAC);
    if (!GetBIOSSerial(g_CurrBIOSSerial, sizeof(g_CurrBIOSSerial)))
        strcpy_s(g_CurrBIOSSerial, sizeof(g_CurrBIOSSerial), "(not available)");
    if (!GetBoardSerial(g_CurrBoardSerial, sizeof(g_CurrBoardSerial)))
        strcpy_s(g_CurrBoardSerial, sizeof(g_CurrBoardSerial), "(not available)");
    if (!GetSystemUUID(g_CurrSystemUUID, sizeof(g_CurrSystemUUID)))
        strcpy_s(g_CurrSystemUUID, sizeof(g_CurrSystemUUID), "(not available)");
    g_CurrVolumeSerialValid = GetVolumeSerialNum(&g_CurrVolumeSerial);
    if (!GetGPUID(g_CurrGPUID, sizeof(g_CurrGPUID)))
        strcpy_s(g_CurrGPUID, sizeof(g_CurrGPUID), "(not available)");
}

// ==================== HWID LOG ====================

BOOL ReadHwidLog() {
    // Driver writes log to C:\hwid_log.bin
    HANDLE hFile = CreateFileA("C:\\ProgramData\\hwid_log.bin", GENERIC_READ, FILE_SHARE_READ,
        NULL, OPEN_EXISTING, 0, NULL);
    if (hFile == INVALID_HANDLE_VALUE) return FALSE;

    DWORD bytesRead = 0;
    ReadFile(hFile, &g_HwidLog, sizeof(HWID_LOG), &bytesRead, NULL);
    CloseHandle(hFile);

    if (bytesRead == sizeof(HWID_LOG) && memcmp(g_HwidLog.Magic, "HWIDLOG", 7) == 0) {
        g_LogLoaded = TRUE;
        return TRUE;
    }
    return FALSE;
}

void SaveHwidLogToDocuments() {
    if (!g_LogLoaded) return;

    // Get Documents folder
    CHAR docsPath[MAX_PATH];
    if (FAILED(SHGetFolderPathA(NULL, CSIDL_PERSONAL, NULL, 0, docsPath))) return;

    CHAR logPath[MAX_PATH];
    sprintf_s(logPath, sizeof(logPath), "%s\\HWID_Spoof_Log.txt", docsPath);

    FILE* f = NULL;
    fopen_s(&f, logPath, "w");
    if (!f) return;

    fprintf(f, "========================================\n");
    fprintf(f, "  HWID SPOOFER - ID LOG\n");
    fprintf(f, "========================================\n\n");

    fprintf(f, "--- DISK ---\n");
    fprintf(f, "  Original Serial:   %s\n", g_HwidLog.OrigDiskSerial);
    fprintf(f, "  Spoofed Serial:    %s\n", g_HwidLog.FakeDiskSerial);
    fprintf(f, "  Original Model:    %s\n", g_HwidLog.OrigModelNumber);
    fprintf(f, "  Spoofed Model:     %s\n", g_HwidLog.FakeModelNumber);
    fprintf(f, "  Original Firmware: %s\n", g_HwidLog.OrigFirmwareRev);
    fprintf(f, "  Spoofed Firmware:  %s\n\n", g_HwidLog.FakeFirmwareRev);

    fprintf(f, "--- BIOS ---\n");
    fprintf(f, "  Original Serial:   %s\n", g_HwidLog.OrigBIOSSerial);
    fprintf(f, "  Spoofed Serial:    %s\n\n", g_HwidLog.FakeBIOSSerial);

    fprintf(f, "--- MOTHERBOARD ---\n");
    fprintf(f, "  Original Serial:   %s\n", g_HwidLog.OrigBoardSerial);
    fprintf(f, "  Spoofed Serial:    %s\n\n", g_HwidLog.FakeBoardSerial);

    fprintf(f, "--- SYSTEM UUID ---\n");
    fprintf(f, "  Original UUID:     %s\n", g_HwidLog.OrigSystemUUID);
    fprintf(f, "  Spoofed UUID:      %s\n\n", g_HwidLog.FakeSystemUUID);

    fprintf(f, "--- NIC / MAC ---\n");
    fprintf(f, "  Original MAC:      %02X:%02X:%02X:%02X:%02X:%02X\n",
        g_HwidLog.OrigMAC[0], g_HwidLog.OrigMAC[1], g_HwidLog.OrigMAC[2],
        g_HwidLog.OrigMAC[3], g_HwidLog.OrigMAC[4], g_HwidLog.OrigMAC[5]);
    fprintf(f, "  Spoofed MAC:       %02X:%02X:%02X:%02X:%02X:%02X\n\n",
        g_HwidLog.FakeMAC[0], g_HwidLog.FakeMAC[1], g_HwidLog.FakeMAC[2],
        g_HwidLog.FakeMAC[3], g_HwidLog.FakeMAC[4], g_HwidLog.FakeMAC[5]);

    fprintf(f, "--- VOLUME ---\n");
    fprintf(f, "  Original Serial:   %08X\n", g_HwidLog.OrigVolumeSerial[0]);
    fprintf(f, "  Spoofed Serial:    %08X\n\n", g_HwidLog.FakeVolumeSerial[0]);

    fprintf(f, "--- GPU ---\n");
    fprintf(f, "  Original ID:       %s\n", g_HwidLog.OrigGPUId);
    fprintf(f, "  Spoofed ID:        %s\n\n", g_HwidLog.FakeGPUId);

    fprintf(f, "========================================\n");
    fprintf(f, "  Saved by HWID Spoofer Manager\n");
    fprintf(f, "========================================\n");

    fclose(f);

    // Also delete the binary log from C:\ (cleanup)
    DeleteFileA("C:\\ProgramData\\hwid_log.bin");
}

// ==================== RANDOM GENERATION ====================

void GenerateRandomSerial(char* buffer, size_t bufferSize) {
    const char* prefixes[] = {"WD-WMA", "WD-WXJ", "S3Y9N", "Z1D2E", "CVEM", "BTPR"};
    int prefixIdx = rand() % 6;
    char suffix[20];
    for (int i = 0; i < 12; i++) {
        int r = rand() % 36;
        suffix[i] = (r < 10) ? ('0' + r) : ('A' + r - 10);
    }
    suffix[12] = '\0';
    sprintf_s(buffer, bufferSize, "%s%s", prefixes[prefixIdx], suffix);
}

void GenerateRandomMAC(UCHAR* mac) {
    for (int i = 0; i < 6; i++)
        mac[i] = (UCHAR)(rand() & 0xFF);
    mac[0] = (mac[0] & 0xFE) | 0x02; // Locally administered, unicast
}

// ==================== SPOOF / REVERT ====================

void UpdateStatus() {
    if (g_SpooferLoaded) {
        strcpy_s(g_StatusText, sizeof(g_StatusText), "ACTIVE");
        g_StatusColor = CLR_GREEN;
    } else {
        strcpy_s(g_StatusText, sizeof(g_StatusText), "INACTIVE");
        g_StatusColor = CLR_RED;
        g_TimeRemaining[0] = '\0';
    }
}

void DoSpoofHWID() {
    // If already loaded, revert first (for "randomize again")
    if (g_SpooferLoaded) {
        UnloadSpooferDriver();
        g_SpooferLoaded = FALSE;
        Sleep(500);
    }

    if (GetFileAttributesA(g_VulnDriverPath) == INVALID_FILE_ATTRIBUTES) {
        if (!ExtractDriverFiles()) {
            MessageBoxA(g_hWnd,
                "Failed to extract embedded driver files.",
                "Extract Error", MB_ICONERROR);
            UpdateStatus();
            return;
        }
    }

    // Load driver
    if (!LoadSpooferDriver()) {
        MessageBoxA(g_hWnd,
            "Failed to load spoofer driver.\n\n"
            "Possible causes:\n"
            "- Test signing not enabled\n"
            "- Memory Integrity (HVCI) is on\n"
            "- Secure Boot blocking unsigned drivers",
            "Driver Error", MB_ICONERROR);
        UpdateStatus();
        return;
    }

    g_SpooferLoaded = TRUE;

    // Set up duration timer
    KillTimer(g_hWnd, IDT_DURATION_TIMER);
    g_SpoofExpiry = 0;
    g_SelectedDuration = (int)SendMessageA(g_hComboDuration, CB_GETCURSEL, 0, 0);

    ULONGLONG durationMs = 0;
    switch (g_SelectedDuration) {
        case DUR_1_DAY:   durationMs = (ULONGLONG)24 * 60 * 60 * 1000; break;
        case DUR_7_DAYS:  durationMs = (ULONGLONG)7 * 24 * 60 * 60 * 1000; break;
        case DUR_30_DAYS: durationMs = (ULONGLONG)30 * 24 * 60 * 60 * 1000; break;
        case DUR_UNTIL_REBOOT:
        default: durationMs = 0; break;
    }

    if (durationMs > 0) {
        g_SpoofExpiry = GetTickCount64() + durationMs;
        SetTimer(g_hWnd, IDT_DURATION_TIMER, (UINT)(durationMs > 0xFFFFFFFF ? 0xFFFFFFFF : durationMs), NULL);
    }

    // Wait a moment, then refresh current IDs
    Sleep(1000);
    RefreshCurrentHWIDs();
    UpdateStatus();

    // Read driver's ID log and save human-readable version to Documents
    Sleep(500);
    if (ReadHwidLog()) {
        SaveHwidLogToDocuments();
    }
}

void DoRevertHWID() {
    if (!g_SpooferLoaded) return;

    UnloadSpooferDriver();
    g_SpooferLoaded = FALSE;
    g_LogLoaded = FALSE;
    g_SpoofExpiry = 0;
    KillTimer(g_hWnd, IDT_DURATION_TIMER);

    CleanupTempFiles();
    CreateHiddenTempDirectory();

    Sleep(500);
    RefreshCurrentHWIDs();
    UpdateStatus();

    MessageBoxA(g_hWnd,
        "Hardware IDs reverted.\n\nA system reboot may be required to fully restore all IDs.",
        "Reverted", MB_ICONINFORMATION);
}

// ==================== ANTI-DETECTION HELPERS ====================

void GenerateRandomHexName(char* buffer, size_t len) {
    static const char hex[] = "0123456789abcdef";
    for (size_t i = 0; i < len - 1; i++) {
        buffer[i] = hex[rand() % 16];
    }
    buffer[len - 1] = '\0';
}

void SecureWipeFile(const char* path) {
    HANDLE hFile = CreateFileA(path, GENERIC_WRITE, 0, NULL,
        OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (hFile == INVALID_HANDLE_VALUE) return;

    LARGE_INTEGER fileSize;
    if (GetFileSizeEx(hFile, &fileSize) && fileSize.QuadPart > 0) {
        DWORD chunkSize = 4096;
        BYTE zeros[4096];
        memset(zeros, 0, sizeof(zeros));

        LARGE_INTEGER pos = {0};
        SetFilePointerEx(hFile, pos, NULL, FILE_BEGIN);

        LONGLONG remaining = fileSize.QuadPart;
        while (remaining > 0) {
            DWORD toWrite = (remaining < chunkSize) ? (DWORD)remaining : chunkSize;
            DWORD written = 0;
            WriteFile(hFile, zeros, toWrite, &written, NULL);
            remaining -= written;
        }
        FlushFileBuffers(hFile);
    }
    CloseHandle(hFile);
    DeleteFileA(path);
}

// ==================== RESOURCE EXTRACTION ====================

BOOL CreateHiddenTempDirectory() {
    char tempPath[MAX_PATH];
    if (GetTempPathA(MAX_PATH, tempPath) == 0) return FALSE;

    // Random folder name that looks like a Windows update cache
    char randDir[17];
    GenerateRandomHexName(randDir, sizeof(randDir));
    sprintf_s(g_TempDir, sizeof(g_TempDir), "%sMicrosoft\\%s", tempPath, randDir);

    // Create parent if needed
    char parentDir[MAX_PATH];
    sprintf_s(parentDir, sizeof(parentDir), "%sMicrosoft", tempPath);
    CreateDirectoryA(parentDir, NULL);

    if (!CreateDirectoryA(g_TempDir, NULL)) {
        if (GetLastError() != ERROR_ALREADY_EXISTS) return FALSE;
    }
    SetFileAttributesA(g_TempDir, FILE_ATTRIBUTE_HIDDEN | FILE_ATTRIBUTE_SYSTEM);

    char randName1[13];
    GenerateRandomHexName(randName1, sizeof(randName1));
    sprintf_s(g_VulnDriverPath, sizeof(g_VulnDriverPath), "%s\\%s.tmp", g_TempDir, randName1);

    // Random service name (8 hex chars)
    GenerateRandomHexName(g_VulnServiceName, 9);
    // iqvw64e.sys always creates device \\Device\\Nal
    sprintf_s(g_VulnDeviceName, sizeof(g_VulnDeviceName), "\\\\.\\Nal");

    return TRUE;
}

BOOL ExtractResource(int resourceId, const char* outputPath) {
    HRSRC hRes = FindResourceA(g_hInst, MAKEINTRESOURCEA(resourceId), RT_RCDATA);
    if (!hRes) return FALSE;

    HGLOBAL hData = LoadResource(g_hInst, hRes);
    if (!hData) return FALSE;

    DWORD size = SizeofResource(g_hInst, hRes);
    PVOID data = LockResource(hData);
    if (!data || size == 0) return FALSE;

    HANDLE hFile = CreateFileA(outputPath, GENERIC_WRITE, 0, NULL,
        CREATE_ALWAYS, FILE_ATTRIBUTE_HIDDEN | FILE_ATTRIBUTE_SYSTEM, NULL);
    if (hFile == INVALID_HANDLE_VALUE) return FALSE;

    DWORD written = 0;
    WriteFile(hFile, data, size, &written, NULL);
    CloseHandle(hFile);

    return (written == size);
}

BOOL ExtractDriverFiles() {
    return ExtractResource(IDR_VULN_SYS, g_VulnDriverPath);
}

void CleanupTempFiles() {
    SecureWipeFile(g_VulnDriverPath);
    RemoveDirectoryA(g_TempDir);
}

// ==================== INTEGRATED KDMAPPER ====================

BOOL LoadVulnerableDriver() {
    if (GetFileAttributesA(g_VulnDriverPath) == INVALID_FILE_ATTRIBUTES)
        return FALSE;

    // Need full path for service creation
    CHAR fullPath[MAX_PATH];
    GetFullPathNameA(g_VulnDriverPath, MAX_PATH, fullPath, NULL);

    SC_HANDLE scm = OpenSCManagerA(NULL, NULL, SC_MANAGER_ALL_ACCESS);
    if (!scm) return FALSE;

    // Use randomized service name
    SC_HANDLE svc = CreateServiceA(scm, g_VulnServiceName, g_VulnServiceName,
        SERVICE_ALL_ACCESS, SERVICE_KERNEL_DRIVER, SERVICE_DEMAND_START,
        SERVICE_ERROR_NORMAL, fullPath, NULL, NULL, NULL, NULL, NULL);

    DWORD createError = GetLastError();
    if (!svc && createError != ERROR_SERVICE_EXISTS) {
        CloseServiceHandle(scm);
        return FALSE;
    }
    if (!svc) {
        svc = OpenServiceA(scm, g_VulnServiceName, SERVICE_ALL_ACCESS);
    }

    if (!StartServiceA(svc, 0, NULL)) {
        DWORD startError = GetLastError();
        if (startError != ERROR_SERVICE_ALREADY_RUNNING) {
            CloseServiceHandle(svc);
            CloseServiceHandle(scm);
            return FALSE;
        }
    }

    CloseServiceHandle(svc);
    CloseServiceHandle(scm);

    // Driver is now loaded in kernel â€” immediately wipe the file from disk
    SecureWipeFile(g_VulnDriverPath);

    g_hVulnDriver = CreateFileA(g_VulnDeviceName, GENERIC_READ | GENERIC_WRITE,
        0, NULL, OPEN_EXISTING, 0, NULL);

    return TRUE;
}

VOID UnloadVulnerableDriver() {
    if (g_hVulnDriver != INVALID_HANDLE_VALUE) {
        CloseHandle(g_hVulnDriver);
        g_hVulnDriver = INVALID_HANDLE_VALUE;
    }
    SC_HANDLE scm = OpenSCManagerA(NULL, NULL, SC_MANAGER_ALL_ACCESS);
    if (scm) {
        // Use the randomized service name
        SC_HANDLE svc = OpenServiceA(scm, g_VulnServiceName, SERVICE_ALL_ACCESS);
        if (svc) {
            SERVICE_STATUS status;
            ControlService(svc, SERVICE_CONTROL_STOP, &status);
            DeleteService(svc);
            CloseServiceHandle(svc);
        }
        CloseServiceHandle(scm);
    }
}

PVOID KM_GetKernelBase() {
    HMODULE ntdll = GetModuleHandleA("ntdll.dll");
    if (!ntdll) return NULL;

    pNtQuerySystemInformation NtQSI =
        (pNtQuerySystemInformation)GetProcAddress(ntdll, "NtQuerySystemInformation");
    if (!NtQSI) return NULL;

    ULONG size = 0;
    NtQSI(11, NULL, 0, &size);

    SYSTEM_MODULE_INFO* modules = (SYSTEM_MODULE_INFO*)malloc(size);
    if (!modules) return NULL;

    if (NtQSI(11, modules, size, &size) != 0) {
        free(modules);
        return NULL;
    }

    PVOID base = modules->Modules[0].ImageBaseAddress;
    free(modules);
    return base;
}

PVOID KM_MapPhysicalMemory(ULONG64 physAddr, SIZE_T size) {
    MAP_IO_SPACE_BUFFER input = {0};
    input.case_number = 0x19;
    input.phys_addr = physAddr;
    input.size = size;
    DWORD returned = 0;
    DeviceIoControl(g_hVulnDriver, IOCTL_NAL_MAP,
        &input, sizeof(input), &input, sizeof(input), &returned, NULL);
    return (PVOID)input.return_ptr;
}

VOID KM_UnmapPhysicalMemory(PVOID virtAddr, SIZE_T size) {
    UNMAP_IO_SPACE_BUFFER input = {0};
    input.case_number = 0x1A;
    input.virt_addr = (ULONG64)virtAddr;
    input.size = (ULONG64)size;
    DWORD returned = 0;
    DeviceIoControl(g_hVulnDriver, IOCTL_NAL_MAP,
        &input, sizeof(input), NULL, 0, &returned, NULL);
}

BOOL KM_CopyKernelMemory(ULONG64 dest, ULONG64 src, SIZE_T size) {
    COPY_MEMORY_BUFFER input = {0};
    input.case_number = 0x33;
    input.source = src;
    input.destination = dest;
    input.length = (ULONG64)size;
    DWORD returned = 0;
    return DeviceIoControl(g_hVulnDriver, IOCTL_NAL_MAP,
        &input, sizeof(input), NULL, 0, &returned, NULL);
}

BOOL KM_ReadKernelMemory(ULONG64 kernelAddr, PVOID buffer, SIZE_T size) {
    return KM_CopyKernelMemory((ULONG64)buffer, kernelAddr, size);
}

BOOL KM_WriteKernelMemory(ULONG64 kernelAddr, PVOID buffer, SIZE_T size) {
    return KM_CopyKernelMemory(kernelAddr, (ULONG64)buffer, size);
}

PVOID KM_GetKernelExport(const char* name) {
    HMODULE kernel = LoadLibraryExA("ntoskrnl.exe", NULL, DONT_RESOLVE_DLL_REFERENCES);
    if (!kernel) return NULL;

    PVOID proc = GetProcAddress(kernel, name);
    if (!proc) { FreeLibrary(kernel); return NULL; }

    ULONG64 offset = (ULONG64)proc - (ULONG64)kernel;
    FreeLibrary(kernel);
    return (PVOID)((ULONG64)g_KernelBase + offset);
}

BOOL KM_ProcessRelocations(PVOID imageBase, PVOID mappedBase, SIZE_T imageSize) {
    (void)imageSize;
    PIMAGE_DOS_HEADER dos = (PIMAGE_DOS_HEADER)imageBase;
    PIMAGE_NT_HEADERS64 nt = (PIMAGE_NT_HEADERS64)((BYTE*)imageBase + dos->e_lfanew);

    PIMAGE_DATA_DIRECTORY relocDir = &nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC];
    if (!relocDir->VirtualAddress) return TRUE;

    LONGLONG delta = (LONGLONG)mappedBase - nt->OptionalHeader.ImageBase;
    PIMAGE_BASE_RELOCATION reloc = (PIMAGE_BASE_RELOCATION)((BYTE*)imageBase + relocDir->VirtualAddress);

    while (reloc->VirtualAddress) {
        DWORD count = (reloc->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) / sizeof(WORD);
        WORD* data = (WORD*)((BYTE*)reloc + sizeof(IMAGE_BASE_RELOCATION));
        for (DWORD i = 0; i < count; i++) {
            WORD type = data[i] >> 12;
            WORD off = data[i] & 0xFFF;
            if (type == IMAGE_REL_BASED_DIR64) {
                PVOID patchAddr = (BYTE*)imageBase + reloc->VirtualAddress + off;
                *(LONGLONG*)patchAddr += delta;
            }
        }
        reloc = (PIMAGE_BASE_RELOCATION)((BYTE*)reloc + reloc->SizeOfBlock);
    }
    return TRUE;
}

BOOL KM_ResolveImports(PVOID imageBase) {
    PIMAGE_DOS_HEADER dos = (PIMAGE_DOS_HEADER)imageBase;
    PIMAGE_NT_HEADERS64 nt = (PIMAGE_NT_HEADERS64)((BYTE*)imageBase + dos->e_lfanew);

    PIMAGE_DATA_DIRECTORY importDir = &nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];
    if (!importDir->VirtualAddress) return TRUE;

    PIMAGE_IMPORT_DESCRIPTOR importDesc = (PIMAGE_IMPORT_DESCRIPTOR)((BYTE*)imageBase + importDir->VirtualAddress);
    while (importDesc->Name) {
        PIMAGE_THUNK_DATA thunk = (PIMAGE_THUNK_DATA)((BYTE*)imageBase + importDesc->FirstThunk);
        PIMAGE_THUNK_DATA origThunk = (PIMAGE_THUNK_DATA)((BYTE*)imageBase + importDesc->OriginalFirstThunk);
        while (origThunk->u1.AddressOfData) {
            PIMAGE_IMPORT_BY_NAME imp = (PIMAGE_IMPORT_BY_NAME)((BYTE*)imageBase + origThunk->u1.AddressOfData);
            PVOID funcAddr = KM_GetKernelExport((const char*)imp->Name);
            if (funcAddr) {
                thunk->u1.Function = (ULONG64)funcAddr;
            }
            thunk++;
            origThunk++;
        }
        importDesc++;
    }
    return TRUE;
}

ULONG64 KM_FindCodeCave(SIZE_T needed) {
    HMODULE kernel = LoadLibraryExA("ntoskrnl.exe", NULL, DONT_RESOLVE_DLL_REFERENCES);
    if (!kernel) return 0;

    PIMAGE_DOS_HEADER dos = (PIMAGE_DOS_HEADER)kernel;
    PIMAGE_NT_HEADERS64 nt = (PIMAGE_NT_HEADERS64)((BYTE*)kernel + dos->e_lfanew);
    PIMAGE_SECTION_HEADER sec = IMAGE_FIRST_SECTION(nt);

    ULONG64 cave = 0;
    for (WORD i = 0; i < nt->FileHeader.NumberOfSections; i++) {
        if (sec[i].Characteristics & IMAGE_SCN_MEM_EXECUTE) {
            DWORD virtualSize = sec[i].Misc.VirtualSize;
            DWORD rawSize = sec[i].SizeOfRawData;
            if (rawSize > virtualSize + needed) {
                cave = (ULONG64)g_KernelBase + sec[i].VirtualAddress + virtualSize;
                cave = (cave + 0xF) & ~0xFULL;
                break;
            }
        }
    }

    FreeLibrary(kernel);
    return cave;
}

BOOL KM_ExecuteInKernel(ULONG64 funcAddr) {
    HMODULE ntdll = GetModuleHandleA("ntdll.dll");
    if (!ntdll) return FALSE;

    pNtQueryIntervalProfile NtQIP =
        (pNtQueryIntervalProfile)GetProcAddress(ntdll, "NtQueryIntervalProfile");
    if (!NtQIP) return FALSE;

    PVOID halDispatch = KM_GetKernelExport("HalDispatchTable");
    if (!halDispatch) return FALSE;

    ULONG64 halDispatch1Addr = (ULONG64)halDispatch + 8;

    ULONG64 originalFunc = 0;
    if (!KM_ReadKernelMemory(halDispatch1Addr, &originalFunc, sizeof(originalFunc)))
        return FALSE;

    if (!KM_WriteKernelMemory(halDispatch1Addr, &funcAddr, sizeof(funcAddr)))
        return FALSE;

    ULONG interval = 0;
    NtQIP(2, &interval);

    KM_WriteKernelMemory(halDispatch1Addr, &originalFunc, sizeof(originalFunc));
    return TRUE;
}

ULONG64 KM_AllocateKernelPool(SIZE_T size) {
    PVOID pExAllocatePool = KM_GetKernelExport("ExAllocatePoolWithTag");
    if (!pExAllocatePool) return 0;

    ULONG64 codeCave = KM_FindCodeCave(128);
    if (!codeCave) return 0;

    ULONG64 resultAddr = codeCave + 80;

    ULONG64 zero = 0;
    KM_WriteKernelMemory(resultAddr, &zero, sizeof(zero));

    unsigned char sc[] = {
        0x53,                                           // push rbx
        0x48, 0x83, 0xEC, 0x20,                        // sub rsp, 0x20
        0x48, 0x31, 0xC9,                              // xor rcx, rcx  (NonPagedPool)
        0x48, 0xBA,                                     // mov rdx, imm64 (size)
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x49, 0xB8,                                     // mov r8, imm64 (tag)
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x48, 0xB8,                                     // mov rax, imm64 (ExAllocatePoolWithTag)
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0xFF, 0xD0,                                     // call rax
        0x48, 0xBB,                                     // mov rbx, imm64 (result store)
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x48, 0x89, 0x03,                              // mov [rbx], rax
        0x48, 0x83, 0xC4, 0x20,                        // add rsp, 0x20
        0x5B,                                           // pop rbx
        0x31, 0xC0,                                     // xor eax, eax
        0xC3                                            // ret
    };

    *(ULONG64*)(sc + 10) = (ULONG64)size;
    *(ULONG64*)(sc + 20) = (ULONG64)0x6B63614D;
    *(ULONG64*)(sc + 30) = (ULONG64)pExAllocatePool;
    *(ULONG64*)(sc + 42) = resultAddr;

    KM_WriteKernelMemory(codeCave, sc, sizeof(sc));

    if (!KM_ExecuteInKernel(codeCave))
        return 0;

    ULONG64 poolAddr = 0;
    KM_ReadKernelMemory(resultAddr, &poolAddr, sizeof(poolAddr));

    return poolAddr;
}

BOOL KM_CallDriverEntry(ULONG64 entryAddr) {
    ULONG64 codeCave = KM_FindCodeCave(128);
    if (!codeCave) return FALSE;

    ULONG64 resultAddr = codeCave + 80;
    ULONG64 zero = 0;
    KM_WriteKernelMemory(resultAddr, &zero, sizeof(zero));

    unsigned char sc[] = {
        0x53,                                           // push rbx
        0x48, 0x83, 0xEC, 0x20,                        // sub rsp, 0x20
        0x48, 0x31, 0xC9,                              // xor rcx, rcx  (DriverObject=NULL)
        0x48, 0x31, 0xD2,                              // xor rdx, rdx  (RegistryPath=NULL)
        0x48, 0xB8,                                     // mov rax, imm64 (DriverEntry)
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0xFF, 0xD0,                                     // call rax
        0x48, 0xBB,                                     // mov rbx, imm64 (result store)
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x48, 0x89, 0x03,                              // mov [rbx], rax
        0x48, 0x83, 0xC4, 0x20,                        // add rsp, 0x20
        0x5B,                                           // pop rbx
        0x31, 0xC0,                                     // xor eax, eax
        0xC3                                            // ret
    };

    *(ULONG64*)(sc + 13) = entryAddr;
    *(ULONG64*)(sc + 25) = resultAddr;

    KM_WriteKernelMemory(codeCave, sc, sizeof(sc));

    if (!KM_ExecuteInKernel(codeCave))
        return FALSE;

    ULONG64 ntStatus = 0;
    KM_ReadKernelMemory(resultAddr, &ntStatus, sizeof(ntStatus));

    return ((LONG)ntStatus >= 0);
}

BOOL KM_MapDriverFromMemory(PVOID fileBuffer, DWORD fileSize) {
    if (!fileBuffer || fileSize < sizeof(IMAGE_DOS_HEADER)) return FALSE;

    PIMAGE_DOS_HEADER dos = (PIMAGE_DOS_HEADER)fileBuffer;
    PIMAGE_NT_HEADERS64 nt = (PIMAGE_NT_HEADERS64)((BYTE*)fileBuffer + dos->e_lfanew);

    SIZE_T imageSize = nt->OptionalHeader.SizeOfImage;
    DWORD entryRVA = nt->OptionalHeader.AddressOfEntryPoint;

    PVOID localImage = VirtualAlloc(NULL, imageSize, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (!localImage) return FALSE;

    memcpy(localImage, fileBuffer, nt->OptionalHeader.SizeOfHeaders);

    PIMAGE_SECTION_HEADER sec = IMAGE_FIRST_SECTION(nt);
    for (WORD i = 0; i < nt->FileHeader.NumberOfSections; i++) {
        if (sec[i].SizeOfRawData > 0) {
            memcpy(
                (BYTE*)localImage + sec[i].VirtualAddress,
                (BYTE*)fileBuffer + sec[i].PointerToRawData,
                sec[i].SizeOfRawData);
        }
    }

    ULONG64 kernelPool = KM_AllocateKernelPool(imageSize);
    if (!kernelPool) {
        VirtualFree(localImage, 0, MEM_RELEASE);
        return FALSE;
    }

    KM_ProcessRelocations(localImage, (PVOID)kernelPool, imageSize);
    KM_ResolveImports(localImage);

    KM_WriteKernelMemory(kernelPool, localImage, imageSize);

    VirtualFree(localImage, 0, MEM_RELEASE);

    ULONG64 entryAddr = kernelPool + entryRVA;
    return KM_CallDriverEntry(entryAddr);
}

// ==================== DRIVER MANAGEMENT ====================

BOOL LoadSpooferDriver() {
    if (!LoadVulnerableDriver()) return FALSE;

    g_KernelBase = KM_GetKernelBase();
    if (!g_KernelBase) {
        UnloadVulnerableDriver();
        return FALSE;
    }

    HRSRC hRes = FindResourceA(g_hInst, MAKEINTRESOURCEA(IDR_SPOOFER_SYS), RT_RCDATA);
    if (!hRes) { UnloadVulnerableDriver(); return FALSE; }

    HGLOBAL hData = LoadResource(g_hInst, hRes);
    if (!hData) { UnloadVulnerableDriver(); return FALSE; }

    DWORD resSize = SizeofResource(g_hInst, hRes);
    PVOID resData = LockResource(hData);
    if (!resData || resSize == 0) { UnloadVulnerableDriver(); return FALSE; }

    if (!KM_MapDriverFromMemory(resData, resSize)) {
        UnloadVulnerableDriver();
        return FALSE;
    }

    UnloadVulnerableDriver();

    RemoveDirectoryA(g_TempDir);

    return TRUE;
}

BOOL UnloadSpooferDriver() {
    UnloadVulnerableDriver();

    SC_HANDLE scm = OpenSCManager(NULL, NULL, SC_MANAGER_ALL_ACCESS);
    if (!scm) return FALSE;

    // Use randomized service name + fallback known names
    BOOL success = FALSE;
    const char* serviceNames[] = { g_VulnServiceName, "HWIDSpoofer" };
    for (int i = 0; i < 2; i++) {
        if (serviceNames[i][0] == '\0') continue;
        SC_HANDLE service = OpenServiceA(scm, serviceNames[i], SERVICE_ALL_ACCESS);
        if (service) {
            SERVICE_STATUS status;
            ControlService(service, SERVICE_CONTROL_STOP, &status);
            DeleteService(service);
            CloseServiceHandle(service);
            success = TRUE;
        }
    }
    CloseServiceHandle(scm);
    return success;
}

// ==================== UTILITIES ====================

BOOL IsAdmin() {
    BOOL isAdmin = FALSE;
    PSID adminGroup = NULL;
    SID_IDENTIFIER_AUTHORITY ntAuthority = SECURITY_NT_AUTHORITY;
    if (AllocateAndInitializeSid(&ntAuthority, 2, SECURITY_BUILTIN_DOMAIN_RID,
                                  DOMAIN_ALIAS_RID_ADMINS, 0, 0, 0, 0, 0, 0, &adminGroup)) {
        CheckTokenMembership(NULL, adminGroup, &isAdmin);
        FreeSid(adminGroup);
    }
    return isAdmin;
}

