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
#include <stdarg.h>
#include <time.h>
#include <iphlpapi.h>
#include <shlobj.h>
#include <commctrl.h>

#include "resource.h"
#include "../shared/hwid_protocol.h"
#include "hwid_comm.h"

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
#define IDT_REFRESH_TIMER    2003

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

/*
 * Extended ID tracking: struct layout is now owned by shared/hwid_protocol.h
 * (HWID_ID_LOG) and delivered via the DriverComm wrapper. The g_HwidLog /
 * g_LogLoaded globals below are thin compatibility shims over g_DriverComm
 * so the rest of the UI code keeps working with minimal churn.
 */
static HWID_DRIVER_COMM g_DriverComm;
#define g_HwidLog   (*HwidComm_GetLog(&g_DriverComm))
#define g_LogLoaded (HwidComm_IsConnected(&g_DriverComm))

static CHAR g_TempDir[MAX_PATH] = {0};
static CHAR g_VulnDriverPath[MAX_PATH] = {0};
static CHAR g_VulnServiceName[32] = {0};
static CHAR g_VulnDeviceName[64] = {0};

static char g_LastMapFail[768];

static void SetLastMapFailV(const char* fmt, ...) {
    va_list ap;
    va_start(ap, fmt);
    vsprintf_s(g_LastMapFail, sizeof(g_LastMapFail), fmt, ap);
    va_end(ap);
}

static void ClearLastMapFail(void) { g_LastMapFail[0] = 0; }

// ==================== KDMAPPER STRUCTURES ====================

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

typedef NTSTATUS(NTAPI* pRtlGetVersion)(PRTL_OSVERSIONINFOW);

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
void SaveHwidLogToDocuments();

static void DbgLog(const char* fmt, ...);

// Kdmapper integrated functions
BOOL LoadVulnerableDriver();
VOID UnloadVulnerableDriver();
PVOID KM_GetKernelBase();
PVOID KM_MapPhysicalMemory(ULONG64 physAddr, SIZE_T size);
VOID KM_UnmapPhysicalMemory(PVOID virtAddr, SIZE_T size);
BOOL KM_CopyKernelMemory(ULONG64 dest, ULONG64 src, SIZE_T size);
BOOL KM_ReadKernelMemory(ULONG64 kernelAddr, PVOID buffer, SIZE_T size);
BOOL KM_WriteKernelMemory(ULONG64 kernelAddr, PVOID buffer, SIZE_T size);
BOOL KM_ReadPhysicalAddress(ULONG64 physAddr, PVOID buffer, SIZE_T size);
BOOL KM_WritePhysicalAddress(ULONG64 physAddr, PVOID buffer, SIZE_T size);
ULONG64 KM_TranslateLinearAddress(ULONG64 dirBase, ULONG64 virtualAddr);
ULONG64 KM_GetDirectoryTableBase();
BOOL KM_WriteToReadOnlyMemory(ULONG64 kernelAddr, PVOID buffer, SIZE_T size);
PVOID KM_GetKernelExport(const char* name);
BOOL KM_ProcessRelocations(PVOID imageBase, PVOID mappedBase, SIZE_T imageSize);
BOOL KM_ResolveImports(PVOID imageBase);
ULONG64 KM_FindCodeCave(SIZE_T needed);
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
        else if (wParam == IDT_REFRESH_TIMER) {
            /* Pull a fresh shared block; driver republishes every 2s with
             * originals filled in as hooks observe them. */
            if (HwidComm_IsConnected(&g_DriverComm)) {
                if (HwidComm_Refresh(&g_DriverComm))
                    InvalidateRect(hWnd, NULL, FALSE);
            } else {
                KillTimer(hWnd, IDT_REFRESH_TIMER);
            }
        }
        else if (wParam == IDT_COUNTDOWN_TIMER) {
            if (g_SpooferLoaded && g_SpoofExpiry > 0) {
                ULONGLONG now = GetTickCount64();
                if (now >= g_SpoofExpiry) {
                    KillTimer(hWnd, IDT_DURATION_TIMER);
                    g_SpoofExpiry = 0;
                    DoRevertHWID();
                    InvalidateRect(hWnd, NULL, TRUE);
                    return 0;
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
                { char vb[32]; sprintf_s(vb, sizeof(vb), "%08X", g_HwidLog.FakeVolumeSerial);
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
            HwidComm_RequestRevert(&g_DriverComm);
            HwidComm_WaitForRevert(&g_DriverComm, 3000);
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

static BOOL GetSMBIOSString(BYTE smbType, BYTE strOffset, char* buffer, size_t bufferSize) {
    typedef struct {
        BYTE  Method; BYTE MajVer; BYTE MinVer; BYTE DmiRev; DWORD Length;
    } SMB_HDR;

    DWORD fwSize = GetSystemFirmwareTable('RSMB', 0, NULL, 0);
    if (fwSize == 0) return FALSE;

    BYTE* data = (BYTE*)malloc(fwSize);
    if (!data) return FALSE;

    if (GetSystemFirmwareTable('RSMB', 0, data, fwSize) != fwSize) {
        free(data);
        return FALSE;
    }

    if (fwSize < sizeof(SMB_HDR)) {
        free(data);
        return FALSE;
    }

    SMB_HDR* hdr = (SMB_HDR*)data;
    if (hdr->Length == 0 || hdr->Length > fwSize - sizeof(SMB_HDR)) {
        free(data);
        return FALSE;
    }
    BYTE* tbl = data + sizeof(SMB_HDR);
    BYTE* tblEnd = tbl + hdr->Length;
    BYTE* ptr = tbl;
    BOOL found = FALSE;

    while (ptr + 4 < tblEnd) {
        BYTE type = ptr[0];
        BYTE length = ptr[1];
        if (length < 4) break;

        if (type == smbType && length > strOffset) {
            BYTE strIdx = ptr[strOffset];
            if (strIdx > 0) {
                BYTE* strings = ptr + length;
                BYTE num = 1;
                while (strings < tblEnd - 1 && !(strings[0] == 0 && strings[1] == 0)) {
                    size_t sl = strnlen_s((char*)strings, (size_t)(tblEnd - strings));
                    if (sl == 0 || sl >= (size_t)(tblEnd - strings)) break;
                    if (num == strIdx && sl > 0) {
                        strncpy_s(buffer, bufferSize, (char*)strings, _TRUNCATE);
                        found = TRUE;
                        break;
                    }
                    strings += sl + 1;
                    num++;
                }
            }
            break;
        }

        ptr += length;
        while (ptr < tblEnd - 1 && !(ptr[0] == 0 && ptr[1] == 0)) ptr++;
        ptr += 2;
    }

    free(data);
    return found;
}

static void TrimAsciiInPlace(char* s) {
    size_t i, len, start = 0, end;
    if (!s) return;
    len = strlen(s);
    while (start < len && (unsigned char)s[start] <= ' ') start++;
    end = len;
    while (end > start && (unsigned char)s[end - 1] <= ' ') end--;
    if (start > 0 && end > start) {
        memmove(s, s + start, end - start);
        s[end - start] = '\0';
    } else if (start > 0) {
        s[0] = '\0';
    } else {
        s[end] = '\0';
    }
    for (i = 0; s[i]; i++) {
        if (s[i] == '\t' || s[i] == '\r' || s[i] == '\n')
            s[i] = ' ';
    }
}

static BOOL IsLowEntropySerial(const char* s) {
    size_t i, len;
    char first = 0;
    BOOL allSame = TRUE;
    if (!s || !s[0]) return TRUE;
    len = strlen(s);
    if (len < 2) return TRUE;
    for (i = 0; i < len; i++) {
        char c = s[i];
        if (c != ' ' && c != '-' && c != '_' && c != '0' && c != '.') {
            if (!first) first = c;
            if (c != first) allSame = FALSE;
        }
    }
    return allSame;
}

/* OEMs often leave placeholder text in the registry; treat as missing so SMBIOS can supply a real value. */
static BOOL IsPlaceholderSerial(const char* s) {
    static const char* bad[] = {
        "System Serial Number",
        "Base Board Serial Number",
        "Default string",
        "Default String",
        "To be filled by O.E.M.",
        "To Be Filled By O.E.M.",
        "O.E.M.",
        "NONE",
        "None",
        "Not Specified",
        "Not Applicable",
        "INVALID",
        "N/A",
        "0",
    };
    size_t i;
    char norm[256];
    if (!s || !s[0]) return TRUE;
    strncpy_s(norm, sizeof(norm), s, _TRUNCATE);
    TrimAsciiInPlace(norm);
    if (!norm[0]) return TRUE;
    if (IsLowEntropySerial(norm)) return TRUE;
    for (i = 0; i < sizeof(bad) / sizeof(bad[0]); i++) {
        if (_stricmp(norm, bad[i]) == 0) return TRUE;
    }
    if (strstr(norm, "To be filled") || strstr(norm, "To Be Filled") ||
        strstr(norm, "Default") || strstr(norm, "Not Specified"))
        return TRUE;
    return FALSE;
}

BOOL GetBIOSSerial(char* buffer, size_t bufferSize) {
    HKEY hKey;
    if (RegOpenKeyExA(HKEY_LOCAL_MACHINE,
            "HARDWARE\\DESCRIPTION\\System\\BIOS", 0, KEY_READ, &hKey) == ERROR_SUCCESS) {
        DWORD size = (DWORD)bufferSize;
        DWORD type = 0;
        LSTATUS res = RegQueryValueExA(hKey, "SystemSerialNumber", NULL, &type, (LPBYTE)buffer, &size);
        RegCloseKey(hKey);
        TrimAsciiInPlace(buffer);
        if (res == ERROR_SUCCESS && type == REG_SZ && buffer[0] != '\0' && !IsPlaceholderSerial(buffer))
            return TRUE;
    }
    if (GetSMBIOSString(1, 0x07, buffer, bufferSize)) {
        TrimAsciiInPlace(buffer);
        if (!IsPlaceholderSerial(buffer))
            return TRUE;
    }
    if (GetSMBIOSString(1, 0x04, buffer, bufferSize)) {
        /* Some firmware places serial-like value in product-name slot; use only as last resort. */
        TrimAsciiInPlace(buffer);
        if (!IsPlaceholderSerial(buffer))
            return TRUE;
    }
    buffer[0] = '\0';
    return FALSE;
}

BOOL GetBoardSerial(char* buffer, size_t bufferSize) {
    HKEY hKey;
    if (RegOpenKeyExA(HKEY_LOCAL_MACHINE,
            "HARDWARE\\DESCRIPTION\\System\\BIOS", 0, KEY_READ, &hKey) == ERROR_SUCCESS) {
        DWORD size = (DWORD)bufferSize;
        DWORD type = 0;
        LSTATUS res = RegQueryValueExA(hKey, "BaseBoardSerialNumber", NULL, &type, (LPBYTE)buffer, &size);
        RegCloseKey(hKey);
        TrimAsciiInPlace(buffer);
        if (res == ERROR_SUCCESS && type == REG_SZ && buffer[0] != '\0' && !IsPlaceholderSerial(buffer))
            return TRUE;
    }
    if (GetSMBIOSString(2, 0x07, buffer, bufferSize)) {
        TrimAsciiInPlace(buffer);
        if (!IsPlaceholderSerial(buffer))
            return TRUE;
    }
    if (GetSMBIOSString(2, 0x06, buffer, bufferSize)) {
        TrimAsciiInPlace(buffer);
        if (!IsPlaceholderSerial(buffer))
            return TRUE;
    }
    buffer[0] = '\0';
    return FALSE;
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

// ==================== HWID LOG (delegated to DriverComm) ====================

/*
 * Legacy ReadHwidLog() replaced by HwidComm_Init() which performs a full
 * handshake (magic + version + size). The wrapper exposes the validated log
 * via HwidComm_GetLog(); callers use g_HwidLog alias above.
 */

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
    fprintf(f, "  Original (registry): %s\n", g_HwidLog.OrigBoardSerial);
    fprintf(f, "  Original (SMBIOS):   %s\n", g_HwidLog.OrigSmbBoardSerial);
    fprintf(f, "  Spoofed Serial:      %s\n\n", g_HwidLog.FakeBoardSerial);

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
    fprintf(f, "  Original Serial:   %08X\n", g_HwidLog.OrigVolumeSerial);
    fprintf(f, "  Spoofed Serial:    %08X\n\n", g_HwidLog.FakeVolumeSerial);

    fprintf(f, "--- GPU ---\n");
    fprintf(f, "  Original ID:       %s\n", g_HwidLog.OrigGPUId);
    fprintf(f, "  Spoofed ID:        %s\n\n", g_HwidLog.FakeGPUId);

    fprintf(f, "========================================\n");
    fprintf(f, "  Saved by HWID Spoofer Manager\n");
    fprintf(f, "========================================\n");

    fclose(f);

    /* Binary shared block cleanup is handled by HwidComm_Shutdown. */
}

// ==================== SPOOF / REVERT ====================

/* SignalDriverRevert replaced by HwidComm_RequestRevert(&g_DriverComm). */

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
    if (g_SpooferLoaded) {
        HwidComm_RequestRevert(&g_DriverComm);
        HwidComm_WaitForRevert(&g_DriverComm, 3000);
        UnloadSpooferDriver();
        HwidComm_Shutdown(&g_DriverComm);
        g_SpooferLoaded = FALSE;
        KillTimer(g_hWnd, IDT_REFRESH_TIMER);
        Sleep(300);
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

    if (!LoadSpooferDriver()) {
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
        UINT timerMs = (durationMs > 0x7FFFFFFF) ? 0x7FFFFFFF : (UINT)durationMs;
        SetTimer(g_hWnd, IDT_DURATION_TIMER, timerMs, NULL);
    }

    // Wait a moment, then refresh current IDs
    Sleep(1000);
    RefreshCurrentHWIDs();
    UpdateStatus();

    /*
     * Handshake with the newly-loaded driver via DriverComm (magic + version
     * + size check, fail-fast on mismatch). Up to 3s wait; driver normally
     * publishes within a few hundred ms of DriverEntry.
     */
    HwidComm_Create(&g_DriverComm, DbgLog);
    if (HwidComm_Init(&g_DriverComm, 3000)) {
        SaveHwidLogToDocuments();
        /*
         * Driver republishes the shared block every 2s (see RevertThread
         * in HelloWorld.c). Poll it from the UI so Orig* values captured
         * lazily by hooks (BIOS SMBIOS serial, disk serial via first
         * IOCTL, MAC via first NDIS query, volume serial on first FS
         * query) appear in the panel without user interaction.
         */
        SetTimer(g_hWnd, IDT_REFRESH_TIMER, 2500, NULL);
    } else {
        DbgLog("DoSpoofHWID: DriverComm handshake FAILED - "
               "driver may not have published shared block");
    }
}

void DoRevertHWID() {
    if (!g_SpooferLoaded) return;

    HwidComm_RequestRevert(&g_DriverComm);
    /* Block until driver confirms HWID_STATUS_REVERTED (hooks removed,
     * registry restored) before unloading - otherwise we race the driver
     * and risk leaving hooks/regvals in place. 3s is enough: revert work
     * is synchronous inside RevertThread. */
    HwidComm_WaitForRevert(&g_DriverComm, 3000);
    UnloadSpooferDriver();
    HwidComm_Shutdown(&g_DriverComm);
    g_SpooferLoaded = FALSE;
    g_SpoofExpiry = 0;
    KillTimer(g_hWnd, IDT_DURATION_TIMER);
    KillTimer(g_hWnd, IDT_REFRESH_TIMER);

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
            if (written == 0) break;
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

// ==================== PRE-FLIGHT / NALFIX ====================

/*
 * Return the file name portion of a path (no directory).
 * Returns pointer into the same buffer; never NULL.
 */
static const char* PathBaseNameA(const char* p) {
    const char* b = p;
    const char* s = p;
    for (; *s; ++s) {
        if (*s == '\\' || *s == '/') b = s + 1;
    }
    return b;
}

/*
 * NalFix: iterate all SERVICE_KERNEL_DRIVER services and stop+delete any
 * whose ImagePath filename matches iqvw64e.sys. This clears leftover
 * instances from crashed previous runs / other mappers that would
 * otherwise own \Device\Nal and cause our own load to silently
 * misbehave. Inspired by VollRagm/NalFix.
 *
 * Skips the service this run is about to install (nameToSkip) so we
 * don't remove the service we're in the middle of creating.
 */
static void NalFix_PurgeExistingIqvw64e(SC_HANDLE scm, const char* nameToSkip) {
    DWORD bytesNeeded = 0, servicesReturned = 0, resumeHandle = 0;

    /* Probe size. */
    EnumServicesStatusExA(scm, SC_ENUM_PROCESS_INFO, SERVICE_DRIVER,
        SERVICE_STATE_ALL, NULL, 0, &bytesNeeded, &servicesReturned,
        &resumeHandle, NULL);
    if (bytesNeeded == 0) return;

    BYTE* buf = (BYTE*)HeapAlloc(GetProcessHeap(), 0, bytesNeeded);
    if (!buf) return;

    DWORD bufSize = bytesNeeded;
    if (!EnumServicesStatusExA(scm, SC_ENUM_PROCESS_INFO, SERVICE_DRIVER,
            SERVICE_STATE_ALL, buf, bufSize, &bytesNeeded,
            &servicesReturned, &resumeHandle, NULL)) {
        DbgLog("NalFix: EnumServicesStatusEx failed (err=%lu)", GetLastError());
        HeapFree(GetProcessHeap(), 0, buf);
        return;
    }

    ENUM_SERVICE_STATUS_PROCESSA* services =
        (ENUM_SERVICE_STATUS_PROCESSA*)buf;

    int purged = 0;
    for (DWORD i = 0; i < servicesReturned; ++i) {
        const char* svcName = services[i].lpServiceName;
        if (!svcName) continue;
        if (nameToSkip && _stricmp(svcName, nameToSkip) == 0) continue;

        SC_HANDLE svc = OpenServiceA(scm, svcName,
            SERVICE_QUERY_CONFIG | SERVICE_STOP | DELETE);
        if (!svc) continue;

        BYTE cfgBuf[4096];
        DWORD cfgNeeded = 0;
        if (QueryServiceConfigA(svc, (LPQUERY_SERVICE_CONFIGA)cfgBuf,
                sizeof(cfgBuf), &cfgNeeded)) {
            LPQUERY_SERVICE_CONFIGA cfg = (LPQUERY_SERVICE_CONFIGA)cfgBuf;
            if (cfg->lpBinaryPathName) {
                const char* imgName = PathBaseNameA(cfg->lpBinaryPathName);
                if (_stricmp(imgName, "iqvw64e.sys") == 0) {
                    SERVICE_STATUS ss;
                    ControlService(svc, SERVICE_CONTROL_STOP, &ss);
                    BOOL del = DeleteService(svc);
                    DbgLog("NalFix: purged stale iqvw64e service '%s' "
                           "(stop ok, delete=%s)",
                           svcName, del ? "OK" : "FAIL");
                    purged++;
                }
            }
        }
        CloseServiceHandle(svc);
    }

    HeapFree(GetProcessHeap(), 0, buf);
    if (purged == 0)
        DbgLog("NalFix: no stale iqvw64e services found");
}

/*
 * Pre-flight checks. Returns TRUE if environment looks OK.
 * On FALSE, SetLastMapFailV has been called with a targeted message
 * surfaced by the "Driver Error - Pre-flight" MessageBox (not Stage 4).
 */
static BOOL PreFlight_Check(const char* driverPath) {
    /* 1. Path must be ASCII-only and contain no spaces. The KDMapper-style
     *    flow calls service APIs with this path; unicode/space breakage is
     *    a classic "driver fails to load for no obvious reason" footgun. */
    for (const char* p = driverPath; *p; ++p) {
        unsigned char c = (unsigned char)*p;
        if (c > 0x7F) {
            DbgLog("PreFlight FAIL: non-ASCII byte 0x%02X in driver path '%s'",
                c, driverPath);
            SetLastMapFailV(
                "Driver path contains non-ASCII characters. Move your user "
                "profile / TEMP directory to an ASCII-only path (no accents, "
                "CJK, etc.) and retry.\nPath: %s", driverPath);
            return FALSE;
        }
    }

    /* 2. HVCI / Memory Integrity check. If enabled, the Nal exploit and
     *    kernel-VA PTE flip are architecturally blocked on Win11 24H2+. */
    {
        HKEY hk = NULL;
        if (RegOpenKeyExA(HKEY_LOCAL_MACHINE,
                "SYSTEM\\CurrentControlSet\\Control\\DeviceGuard\\Scenarios"
                "\\HypervisorEnforcedCodeIntegrity",
                0, KEY_READ, &hk) == ERROR_SUCCESS) {
            DWORD enabled = 0, sz = sizeof(enabled);
            if (RegQueryValueExA(hk, "Enabled", NULL, NULL,
                    (LPBYTE)&enabled, &sz) == ERROR_SUCCESS && enabled != 0) {
                DbgLog("PreFlight: HVCI registry Enabled=%lu "
                       "(Memory Integrity is ON)", enabled);
                SetLastMapFailV(
                    "Memory Integrity (HVCI) is enabled. Disable it in "
                    "Windows Security -> Device security -> Core isolation, "
                    "reboot, then retry. See README 'Setup Guide'.");
                RegCloseKey(hk);
                return FALSE;
            }
            RegCloseKey(hk);
        }
    }

    /* 3. Anti-cheat driver check. If vgk/BEDaisy/EasyAntiCheat is already
     *    loaded, kernel writes will typically be observed/blocked long
     *    before we finish mapping. Warn loudly rather than silently fail. */
    {
        static const char* ac_services[] = {
            "vgk",              /* Riot Vanguard kernel driver */
            "vgc",              /* Riot Vanguard user service */
            "BEDaisy",          /* BattlEye kernel driver */
            "EasyAntiCheat",    /* EAC user service */
            "ESEADriver2",      /* ESEA */
            NULL
        };
        SC_HANDLE scm = OpenSCManagerA(NULL, NULL,
            SC_MANAGER_CONNECT | SC_MANAGER_ENUMERATE_SERVICE);
        if (scm) {
            for (int i = 0; ac_services[i]; ++i) {
                SC_HANDLE svc = OpenServiceA(scm, ac_services[i],
                    SERVICE_QUERY_STATUS);
                if (!svc) continue;
                SERVICE_STATUS st = {0};
                if (QueryServiceStatus(svc, &st) &&
                        st.dwCurrentState != SERVICE_STOPPED) {
                    DbgLog("PreFlight: anti-cheat '%s' is running "
                        "(state=%lu) - mapping will likely be blocked",
                        ac_services[i], st.dwCurrentState);
                    SetLastMapFailV(
                        "Anti-cheat service '%s' is running. Vanguard/BE/EAC "
                        "load at boot and block kernel mappers. Close the "
                        "game launcher completely (Task Manager -> End Task) "
                        "and reboot before spoofing.",
                        ac_services[i]);
                    CloseServiceHandle(svc);
                    CloseServiceHandle(scm);
                    return FALSE;
                }
                CloseServiceHandle(svc);
            }
            CloseServiceHandle(scm);
        }
    }

    return TRUE;
}

// ==================== INTEGRATED KDMAPPER ====================

BOOL LoadVulnerableDriver() {
    DbgLog("LoadVulnDriver: checking file at %s", g_VulnDriverPath);
    if (GetFileAttributesA(g_VulnDriverPath) == INVALID_FILE_ATTRIBUTES) {
        DbgLog("LoadVulnDriver FAIL: file not found (err=%lu)", GetLastError());
        return FALSE;
    }

    WIN32_FILE_ATTRIBUTE_DATA fad;
    if (GetFileAttributesExA(g_VulnDriverPath, GetFileExInfoStandard, &fad)) {
        ULONG64 sz = ((ULONG64)fad.nFileSizeHigh << 32) | fad.nFileSizeLow;
        DbgLog("LoadVulnDriver: file size = %llu bytes", sz);
    }

    CHAR fullPath[MAX_PATH];
    GetFullPathNameA(g_VulnDriverPath, MAX_PATH, fullPath, NULL);
    DbgLog("LoadVulnDriver: full path = %s", fullPath);

    SC_HANDLE scm = OpenSCManagerA(NULL, NULL, SC_MANAGER_ALL_ACCESS);
    if (!scm) {
        DbgLog("LoadVulnDriver FAIL: OpenSCManager (err=%lu)", GetLastError());
        return FALSE;
    }

    /* NalFix: clear any stale iqvw64e services before creating our own,
     * so \Device\Nal is free for our DriverEntry to create. */
    NalFix_PurgeExistingIqvw64e(scm, g_VulnServiceName);

    SC_HANDLE svc = CreateServiceA(scm, g_VulnServiceName, g_VulnServiceName,
        SERVICE_ALL_ACCESS, SERVICE_KERNEL_DRIVER, SERVICE_DEMAND_START,
        SERVICE_ERROR_NORMAL, fullPath, NULL, NULL, NULL, NULL, NULL);

    DWORD createError = GetLastError();
    DbgLog("LoadVulnDriver: CreateService=%s (err=%lu)", svc ? "OK" : "FAIL", createError);
    if (!svc && createError != ERROR_SERVICE_EXISTS) {
        CloseServiceHandle(scm);
        return FALSE;
    }
    if (!svc) {
        svc = OpenServiceA(scm, g_VulnServiceName, SERVICE_ALL_ACCESS);
        DbgLog("LoadVulnDriver: OpenService=%s", svc ? "OK" : "FAIL");
    }

    DbgLog("LoadVulnDriver: >>> ABOUT TO CALL StartServiceA <<<");
    DbgLog("LoadVulnDriver: If log ends here, BSOD is in iqvw64e.sys DriverEntry");

    if (!StartServiceA(svc, 0, NULL)) {
        DWORD startError = GetLastError();
        DbgLog("LoadVulnDriver: StartService failed (err=%lu)", startError);
        if (startError != ERROR_SERVICE_ALREADY_RUNNING) {
            CloseServiceHandle(svc);
            CloseServiceHandle(scm);
            return FALSE;
        }
        DbgLog("LoadVulnDriver: service already running, continuing");
    } else {
        DbgLog("LoadVulnDriver: StartService OK - driver loaded");
    }

    CloseServiceHandle(svc);
    CloseServiceHandle(scm);

    SecureWipeFile(g_VulnDriverPath);

    DbgLog("LoadVulnDriver: opening device %s", g_VulnDeviceName);
    g_hVulnDriver = CreateFileA(g_VulnDeviceName, GENERIC_READ | GENERIC_WRITE,
        0, NULL, OPEN_EXISTING, 0, NULL);
    DbgLog("LoadVulnDriver: device handle=0x%llX (err=%lu)",
        (ULONG64)g_hVulnDriver, GetLastError());

    return (g_hVulnDriver != INVALID_HANDLE_VALUE);
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
    LPVOID drivers[1024];
    DWORD needed = 0;
    if (EnumDeviceDrivers(drivers, sizeof(drivers), &needed) && needed >= sizeof(LPVOID)) {
        return drivers[0];
    }

    HMODULE ntdll = GetModuleHandleA("ntdll.dll");
    if (!ntdll) return NULL;

    pNtQuerySystemInformation NtQSI =
        (pNtQuerySystemInformation)GetProcAddress(ntdll, "NtQuerySystemInformation");
    if (!NtQSI) return NULL;

    ULONG size = 0;
    NtQSI(11, NULL, 0, &size);
    if (size == 0) return NULL;

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
    BOOL ok = DeviceIoControl(g_hVulnDriver, IOCTL_NAL_MAP,
        &input, sizeof(input), &input, sizeof(input), &returned, NULL);
    DbgLog("    MapPhys: PA=0x%llX size=%llu -> status=0x%llX VA=0x%llX (ioctl=%s, err=%lu)",
        physAddr, (ULONG64)size, input.return_status, (ULONG64)input.return_ptr,
        ok ? "OK" : "FAIL", GetLastError());
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
    BOOL ok = DeviceIoControl(g_hVulnDriver, IOCTL_NAL_MAP,
        &input, sizeof(input), NULL, 0, &returned, NULL);
    if (!ok) {
        DbgLog("    CopyMem FAIL: dst=0x%llX src=0x%llX size=%llu err=%lu",
            dest, src, (ULONG64)size, GetLastError());
    }
    return ok;
}

BOOL KM_ReadKernelMemory(ULONG64 kernelAddr, PVOID buffer, SIZE_T size) {
    return KM_CopyKernelMemory((ULONG64)buffer, kernelAddr, size);
}

BOOL KM_WriteKernelMemory(ULONG64 kernelAddr, PVOID buffer, SIZE_T size) {
    return KM_CopyKernelMemory(kernelAddr, (ULONG64)buffer, size);
}

BOOL KM_ReadPhysicalAddress(ULONG64 physAddr, PVOID buffer, SIZE_T size) {
    ULONG64 pageBase = physAddr & ~0xFFFULL;
    ULONG64 pageOffset = physAddr & 0xFFF;

    if (pageOffset + size > 0x1000) return FALSE;

    PVOID mapped = KM_MapPhysicalMemory(pageBase, 0x1000);
    if (!mapped) return FALSE;

    BOOL ok = KM_CopyKernelMemory((ULONG64)buffer, (ULONG64)mapped + pageOffset, size);
    KM_UnmapPhysicalMemory(mapped, 0x1000);
    return ok;
}

BOOL KM_WritePhysicalAddress(ULONG64 physAddr, PVOID buffer, SIZE_T size) {
    ULONG64 pageBase = physAddr & ~0xFFFULL;
    ULONG64 pageOffset = physAddr & 0xFFF;

    if (pageOffset + size > 0x1000) return FALSE;

    PVOID mapped = KM_MapPhysicalMemory(pageBase, 0x1000);
    if (!mapped) return FALSE;

    BOOL ok = KM_CopyKernelMemory((ULONG64)mapped + pageOffset, (ULONG64)buffer, size);
    KM_UnmapPhysicalMemory(mapped, 0x1000);
    return ok;
}

ULONG64 KM_TranslateLinearAddress(ULONG64 dirBase, ULONG64 virtualAddr) {
    /* CR3: physical frame of PML4; low bits may hold PCID / flags */
    ULONG64 cr3 = dirBase & 0xFFFFFFFFFFFFF000ULL;

    USHORT pml4Idx  = (USHORT)((virtualAddr >> 39) & 0x1FF);
    USHORT pdptIdx  = (USHORT)((virtualAddr >> 30) & 0x1FF);
    USHORT pdIdx    = (USHORT)((virtualAddr >> 21) & 0x1FF);
    USHORT ptIdx    = (USHORT)((virtualAddr >> 12) & 0x1FF);

    ULONG64 pml4e = 0;
    if (!KM_ReadPhysicalAddress(cr3 + pml4Idx * 8, &pml4e, sizeof(pml4e)))
        return 0;
    if (!(pml4e & 1)) return 0;

    ULONG64 pdpte = 0;
    if (!KM_ReadPhysicalAddress((pml4e & 0xFFFFFFFFFF000ULL) + pdptIdx * 8, &pdpte, sizeof(pdpte)))
        return 0;
    if (!(pdpte & 1)) return 0;
    if (pdpte & 0x80)
        return (pdpte & 0xFFFFC0000000ULL) + (virtualAddr & 0x3FFFFFFFULL);

    ULONG64 pde = 0;
    if (!KM_ReadPhysicalAddress((pdpte & 0xFFFFFFFFFF000ULL) + pdIdx * 8, &pde, sizeof(pde)))
        return 0;
    if (!(pde & 1)) return 0;
    if (pde & 0x80)
        return (pde & 0xFFFFFE00000ULL) + (virtualAddr & 0x1FFFFFULL);

    ULONG64 pte = 0;
    if (!KM_ReadPhysicalAddress((pde & 0xFFFFFFFFFF000ULL) + ptIdx * 8, &pte, sizeof(pte)))
        return 0;
    if (!(pte & 1)) return 0;

    return (pte & 0xFFFFFFFFFF000ULL) + (virtualAddr & 0xFFFULL);
}

ULONG64 KM_GetDirectoryTableBase() {
    PVOID pInitProc = KM_GetKernelExport("PsInitialSystemProcess");
    if (!pInitProc) return 0;

    ULONG64 eprocess = 0;
    if (!KM_ReadKernelMemory((ULONG64)pInitProc, &eprocess, sizeof(eprocess)))
        return 0;
    if (!eprocess) return 0;

    ULONG64 dirBase = 0;
    if (!KM_ReadKernelMemory(eprocess + 0x28, &dirBase, sizeof(dirBase)))
        return 0;

    return dirBase;
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

/* Physical address of the PTE/PDE/PDPTE slot that maps this VA (4K, 2MB, or 1GB page). */
static ULONG64 KM_GetPageTableEntryPhysicalAddress(ULONG64 dirBaseRaw, ULONG64 virtualAddr) {
    ULONG64 cr3 = dirBaseRaw & 0xFFFFFFFFFFFFF000ULL;

    USHORT pml4Idx = (USHORT)((virtualAddr >> 39) & 0x1FF);
    USHORT pdptIdx = (USHORT)((virtualAddr >> 30) & 0x1FF);
    USHORT pdIdx   = (USHORT)((virtualAddr >> 21) & 0x1FF);
    USHORT ptIdx   = (USHORT)((virtualAddr >> 12) & 0x1FF);

    ULONG64 pml4e = 0;
    if (!KM_ReadPhysicalAddress(cr3 + pml4Idx * 8, &pml4e, sizeof(pml4e)))
        return 0;
    if (!(pml4e & 1)) return 0;

    ULONG64 pdpt_phys = pml4e & 0xFFFFFFFFFF000ULL;

    ULONG64 pdpte = 0;
    if (!KM_ReadPhysicalAddress(pdpt_phys + pdptIdx * 8, &pdpte, sizeof(pdpte)))
        return 0;
    if (!(pdpte & 1)) return 0;
    if (pdpte & 0x80)
        return pdpt_phys + pdptIdx * 8; /* 1GB page: modify PDPTE */

    ULONG64 pd_phys = pdpte & 0xFFFFFFFFFF000ULL;
    ULONG64 pde = 0;
    if (!KM_ReadPhysicalAddress(pd_phys + pdIdx * 8, &pde, sizeof(pde)))
        return 0;
    if (!(pde & 1)) return 0;
    if (pde & 0x80)
        return pd_phys + pdIdx * 8; /* 2MB page: modify PDE */

    ULONG64 pt_phys = pde & 0xFFFFFFFFFF000ULL;
    return pt_phys + ptIdx * 8;
}

/* Pick a CR3 that actually translates KernelBase -> MZ at the expected physical frame. */
static ULONG64 KM_GetVerifiedDirectoryTableBase(void) {
    PVOID pInitProc = KM_GetKernelExport("PsInitialSystemProcess");
    if (!pInitProc) return 0;

    ULONG64 eprocess = 0;
    if (!KM_ReadKernelMemory((ULONG64)pInitProc, &eprocess, sizeof(eprocess)) || !eprocess)
        return 0;

    static const ULONG64 kprocessOffsets[] = { 0x28, 0x158 };
    for (ULONG i = 0; i < sizeof(kprocessOffsets) / sizeof(kprocessOffsets[0]); i++) {
        ULONG64 dir = 0;
        if (!KM_ReadKernelMemory(eprocess + kprocessOffsets[i], &dir, sizeof(dir)) || !dir)
            continue;
        ULONG64 phys = KM_TranslateLinearAddress(dir, (ULONG64)g_KernelBase);
        if (!phys) continue;
        USHORT mz = 0;
        if (!KM_ReadPhysicalAddress(phys, &mz, sizeof(mz))) continue;
        if (mz == 0x5A4D)
            return dir;
    }

    return 0;
}

static BOOL KM_IsCanonicalKernelVa(ULONG64 va) {
    return (va >= 0xFFFF800000000000ULL && va <= 0xFFFFFFFFFFFFFFFFULL);
}

/* Return TRUE iff v looks like a valid KASLR'd PTE_BASE:
 *   - canonical kernel address (top 17 bits all 1)
 *   - lower 39 bits zero (PTE_BASE = PML4-index * 2^39, sign-extended)
 *   - in the Windows kernel-half PML4 range (indices 256..511)
 */
static BOOL KM_LooksLikePteBase(ULONG64 v) {
    if ((v >> 47) != 0x1FFFF)        return FALSE; /* not canonical kernel */
    if (v & 0x7FFFFFFFFFULL)         return FALSE; /* lower 39 bits non-zero */
    if (v < 0xFFFF800000000000ULL)   return FALSE; /* below PML4 index 256 */
    if (v > 0xFFFFFF8000000000ULL)   return FALSE; /* above  PML4 index 511 */
    return TRUE;
}

/*
 * Scan the RUNNING ntoskrnl kernel image (read via case 0x33) for the MiGetPteAddress
 * byte pattern to recover the KASLR'd PTE_BASE at runtime.
 *
 * Why the running image, not the on-disk file:
 *   PTE_BASE is randomised at boot and patched into the live kernel.  The PE file
 *   on disk holds placeholder zeros, so a user-mode scan always returns nothing.
 *
 * Anchor: any REX.W SAR/SHR r64, 9  — bits: (48|49) C1 (E8-EF|F8-FF) 09
 *   This is the only instruction needed to compute a PTE index from a VA and appears
 *   at the start of MiGetPteAddress on every known x64 Windows 10/11 build.
 *   Searching 50 bytes both before and after the anchor covers all known orderings.
 *
 * Two value-encoding variants handled:
 *   A) REX.W MOV Rn, imm64  — PTE_BASE baked directly into the instruction
 *   B) REX.W ADD/MOV Rn, [RIP+disp32] — PTE_BASE in a .data slot; follow reference
 *
 * Safety: only IMAGE_SCN_MEM_DISCARDABLE (freed INIT) sections are skipped —
 * those VAs are genuinely unmapped after init and would fault case 0x33.
 * PAGE and PAGELK sections are included: PAGELK is page-locked (non-pageable);
 * PAGE sections can soft-page-in at PASSIVE_LEVEL, which is safe.
 */
static ULONG64 KM_ScanKernelImageForPteBase(void) {
    ULONG64 kbase = (ULONG64)g_KernelBase;
    if (!kbase) return 0;

    BYTE hdr[0x2000];
    if (!KM_ReadKernelMemory(kbase, hdr, sizeof(hdr))) return 0;

    PIMAGE_DOS_HEADER dos = (PIMAGE_DOS_HEADER)hdr;
    if (dos->e_magic != IMAGE_DOS_SIGNATURE) return 0;
    if ((DWORD)dos->e_lfanew + sizeof(IMAGE_NT_HEADERS64) > sizeof(hdr)) return 0;

    PIMAGE_NT_HEADERS64 nt  = (PIMAGE_NT_HEADERS64)(hdr + dos->e_lfanew);
    if (nt->Signature != IMAGE_NT_SIGNATURE) return 0;

    PIMAGE_SECTION_HEADER sec = IMAGE_FIRST_SECTION(nt);
    WORD   nsec    = nt->FileHeader.NumberOfSections;
    ULONG64 pteBase = 0;

    const DWORD CHUNK   = 0x8000;  /* 32 KB per IOCTL */
    const DWORD OVERLAP = 60;      /* bytes backed-up between chunks (covers 50-byte window) */
    BYTE* buf = (BYTE*)malloc(CHUNK);
    if (!buf) return 0;

    WORD i;
    for (i = 0; i < nsec && !pteBase; i++) {
        DWORD chars = sec[i].Characteristics;
        if (!(chars & IMAGE_SCN_MEM_EXECUTE))  continue; /* not code */
        if (chars & IMAGE_SCN_MEM_DISCARDABLE) continue; /* freed INIT — truly unmapped */

        ULONG64 secVA   = kbase + sec[i].VirtualAddress;
        DWORD   secSize = sec[i].Misc.VirtualSize;
        if (secSize < 4 || secSize > 0x1800000) continue; /* sanity: skip empty / >24 MB */

        DWORD off = 0;
        while (off < secSize && !pteBase) {
            DWORD rdSz = secSize - off;
            if (rdSz > CHUNK) rdSz = CHUNK;

            if (!KM_ReadKernelMemory(secVA + off, buf, rdSz)) {
                off += rdSz; /* skip unreadable chunk and continue */
                continue;
            }

            DWORD j;
            for (j = 0; j + 4 <= rdSz && !pteBase; j++) {
                BYTE b0 = buf[j], b1 = buf[j+1], b2 = buf[j+2], b3 = buf[j+3];

                /* Anchor: REX.W SAR or SHR r64, 9
                   Encoding: (0x48|0x49) 0xC1 (0xE8..0xEF | 0xF8..0xFF) 0x09 */
                if (b3 != 0x09) continue;
                if (b1 != 0xC1) continue;
                if (b0 != 0x48 && b0 != 0x49) continue;
                if (!((b2 >= 0xE8 && b2 <= 0xEF) || (b2 >= 0xF8 && b2 <= 0xFF))) continue;

                /* Search window: 50 bytes before anchor + 50 bytes after */
                DWORD wstart = (j >= 50) ? j - 50 : 0;
                DWORD wend   = j + 4 + 50;
                if (wend > rdSz) wend = rdSz;

                DWORD k;
                for (k = wstart; k < wend && !pteBase; k++) {
                    if (k + 2 >= rdSz) break;
                    BYTE c0 = buf[k], c1 = buf[k+1];

                    /* Variant A: REX.W MOV Rn, imm64  (10 bytes total) */
                    if (k + 10 <= rdSz &&
                        (c0 == 0x48 || c0 == 0x49) && c1 >= 0xB8 && c1 <= 0xBF) {
                        ULONG64 cand = 0;
                        memcpy(&cand, &buf[k+2], 8);
                        if (KM_LooksLikePteBase(cand))
                            pteBase = cand;
                        continue;
                    }

                    /* Variant B: REX.W ADD/MOV Rn, [RIP+disp32]  (7 bytes)
                       REX.W ADD: (48|4C) 03 (ModRM & 0xC7 == 0x05)
                       REX.W MOV: (48|4C) 8B (ModRM & 0xC7 == 0x05) */
                    if (k + 7 <= rdSz && (c0 == 0x48 || c0 == 0x4C) &&
                        (c1 == 0x03 || c1 == 0x8B) &&
                        ((buf[k+2] & 0xC7) == 0x05)) {
                        INT32 disp32 = 0;
                        memcpy(&disp32, &buf[k+3], 4);
                        ULONG64 instrVA  = secVA + off + k;
                        ULONG64 targetVA = (ULONG64)((LONG64)(instrVA + 7) + disp32);
                        if (KM_IsCanonicalKernelVa(targetVA)) {
                            ULONG64 cand = 0;
                            if (KM_ReadKernelMemory(targetVA, &cand, 8) &&
                                KM_LooksLikePteBase(cand))
                                pteBase = cand;
                        }
                    }
                }
            }

            off += (rdSz > OVERLAP) ? (rdSz - OVERLAP) : rdSz;
        }
    }

    free(buf);
    return pteBase;
}

/*
 * Find PTE_BASE by scanning self-reference PML4 indices (256..511). Anchored at the
 * classic Win7 reference index 0x1ED -> 0xFFFFF68000000000 (see Windows self-map layout).
 * NOTE: this probes kernel addresses with case 0x33 — use only when safe to do so.
 */
static ULONG64 KM_FindPteBaseForSystem(void) {
    ULONG64 kbase = (ULONG64)g_KernelBase;
    ULONG idx;

    for (idx = 256; idx < 512; idx++) {
        ULONG64 pteBase = 0xFFFFF68000000000ULL +
            (((LONG64)(ULONG64)idx - (LONG64)0x1ED) << 39);
        ULONG64 pteAddr = pteBase + (((LONG64)kbase >> 9) & 0x7FFFFFFFF8);
        ULONG64 pteVal = 0;
        ULONG64 pteAddr2;
        ULONG64 pteVal2 = 0;
        ULONG64 pfn1;
        ULONG64 pfn2;

        if (!KM_IsCanonicalKernelVa(pteAddr))
            continue;
        if (!KM_ReadKernelMemory(pteAddr, &pteVal, sizeof(pteVal)))
            continue;
        if (!(pteVal & 1))
            continue;

        pteAddr2 = pteBase + (((LONG64)(kbase + 0x1000) >> 9) & 0x7FFFFFFFF8);
        if (!KM_ReadKernelMemory(pteAddr2, &pteVal2, sizeof(pteVal2)))
            continue;
        if (!(pteVal2 & 1))
            continue;
        pfn1 = (pteVal >> 12) & 0xFFFFFFFFFULL;
        pfn2 = (pteVal2 >> 12) & 0xFFFFFFFFFULL;
        if (pfn2 == pfn1 + 1)
            return pteBase;
    }
    for (idx = 256; idx < 512; idx++) {
        ULONG64 pteBase = 0xFFFFF68000000000ULL +
            (((LONG64)(ULONG64)idx - (LONG64)0x1ED) << 39);
        ULONG64 pteAddr = pteBase + (((LONG64)kbase >> 9) & 0x7FFFFFFFF8);
        ULONG64 pteVal = 0;
        if (!KM_IsCanonicalKernelVa(pteAddr))
            continue;
        if (!KM_ReadKernelMemory(pteAddr, &pteVal, sizeof(pteVal)))
            continue;
        if ((pteVal & 1) && ((pteVal >> 12) & 0xFFFFFFFFFULL) != 0)
            return pteBase;
    }
    return 0;
}

/* PTE_BASE - 0x80000000 == PDE_BASE on NT-style x64 self-map (Vista+). Try PTE slot then PDE for large pages. */
static BOOL KM_TryKernelVaWritableFlip(ULONG64 pteBase, ULONG64 kernelAddr, PVOID buffer, SIZE_T size) {
    ULONG64 pteSlot = pteBase + (((LONG64)kernelAddr >> 9) & 0x7FFFFFFFF8);
    ULONG64 pdeBase = pteBase - 0x80000000ULL;
    ULONG64 pdeSlot = pdeBase + (((LONG64)kernelAddr >> 21) & 0x7FFFFFFFF8);
    ULONG64 slots[2];
    const char* names[2];
    int si;

    slots[0] = pteSlot;
    names[0] = "PTE";
    slots[1] = pdeSlot;
    names[1] = "PDE";

    for (si = 0; si < 2; si++) {
        ULONG64 slot = slots[si];
        ULONG64 old = 0;
        ULONG64 newv;
        BOOL ok;
        BYTE v = 0;
        BOOL vr;

        if (!KM_IsCanonicalKernelVa(slot))
            continue;
        /* PDE slot must lie in the expected PDE range [PTE_BASE-512MB, PTE_BASE).
           If it falls outside, PTE_BASE is wrong — abort rather than read an
           unmapped kernel address and take a BSOD. */
        if (si == 1 && (slot >= pteBase || slot < pteBase - 0x80000000ULL)) {
            DbgLog("  PteFlip[PDE]: slot 0x%llX outside valid PDE range — PTE_BASE likely wrong, aborting", slot);
            break;
        }
        DbgLog("  PteFlip[%s]: reading slot=0x%llX", names[si], slot);
        if (!KM_ReadKernelMemory(slot, &old, sizeof(old))) {
            DbgLog("  PteFlip[%s]: slot read FAILED (DeviceIoControl error)", names[si]);
            continue;
        }
        DbgLog("  PteFlip[%s]: slot val=0x%llX", names[si], old);
        if (!(old & 1))
            continue;

        newv = old | 0x2ULL;
        if (newv == old) {
            DbgLog("  PteFlip[%s]: slot already R/W, writing target directly...", names[si]);
            ok = KM_WriteKernelMemory(kernelAddr, buffer, size);
            vr = KM_ReadKernelMemory(kernelAddr, &v, 1);
            if (ok && vr && v == ((BYTE*)buffer)[0]) {
                DbgLog("  WriteToReadOnly: kernel VA slot already R/W (%s 0x%llX)", names[si], slot);
                return TRUE;
            }
            DbgLog("  PteFlip[%s]: direct write failed (ok=%d vr=%d)", names[si], (int)ok, (int)vr);
            continue;
        }

        DbgLog("  PteFlip[%s]: writing new val=0x%llX to slot...", names[si], newv);
        if (!KM_WriteKernelMemory(slot, &newv, sizeof(newv))) {
            DbgLog("  PteFlip[%s]: SLOT WRITE FAILED — PTE page may be protected (KDP?)", names[si]);
            continue;
        }
        DbgLog("  PteFlip[%s]: slot written, writing shellcode to target 0x%llX...", names[si], kernelAddr);

        ok = KM_WriteKernelMemory(kernelAddr, buffer, size);
        DbgLog("  PteFlip[%s]: shellcode write returned ok=%d", names[si], (int)ok);
        vr = KM_ReadKernelMemory(kernelAddr, &v, 1);
        KM_WriteKernelMemory(slot, &old, sizeof(old));
        DbgLog("  PteFlip[%s]: slot restored", names[si]);

        if (ok && vr && v == ((BYTE*)buffer)[0]) {
            DbgLog("  WriteToReadOnly: kernel VA %s flip OK at 0x%llX", names[si], slot);
            return TRUE;
        }
    }
    return FALSE;
}

BOOL KM_WriteToReadOnlyMemory(ULONG64 kernelAddr, PVOID buffer, SIZE_T size) {
    BYTE verify = 0;
    BOOL vr = FALSE;

    DbgLog("  WriteToReadOnly: VA=0x%llX, size=%llu", kernelAddr, (ULONG64)size);

    ULONG64 dirBase = KM_GetVerifiedDirectoryTableBase();
    if (dirBase) {
        ULONG64 ptePhys = KM_GetPageTableEntryPhysicalAddress(dirBase, kernelAddr);
        if (ptePhys) {
            DbgLog("  WriteToReadOnly: PTE/PDE slot PA=0x%llX (flip RW via physical map)", ptePhys);

            ULONG64 oldEntry = 0;
            if (KM_ReadPhysicalAddress(ptePhys, &oldEntry, sizeof(oldEntry))) {
                ULONG64 newEntry = oldEntry | 0x2ULL;
                BOOL flipped = (newEntry != oldEntry);

                if (flipped) {
                    if (KM_WritePhysicalAddress(ptePhys, &newEntry, sizeof(newEntry))) {
                        BOOL ok = KM_WriteKernelMemory(kernelAddr, buffer, size);
                        verify = 0;
                        vr = KM_ReadKernelMemory(kernelAddr, &verify, 1);
                        KM_WritePhysicalAddress(ptePhys, &oldEntry, sizeof(oldEntry));
                        if (ok && vr && verify == ((BYTE*)buffer)[0]) {
                            DbgLog("  WriteToReadOnly: physical PTE flip + IOCTL copy succeeded");
                            return TRUE;
                        }
                        DbgLog("  WriteToReadOnly: physical flip wrote but verify failed (ok=%d vr=%d)", (int)ok, (int)vr);
                    } else
                        DbgLog("  WriteToReadOnly: physical flip write failed (MmMapIoSpace RAM?)");
                } else {
                    BOOL ok = KM_WriteKernelMemory(kernelAddr, buffer, size);
                    verify = 0;
                    vr = KM_ReadKernelMemory(kernelAddr, &verify, 1);
                    if (ok && vr && verify == ((BYTE*)buffer)[0]) {
                        DbgLog("  WriteToReadOnly: physical path slot already R/W");
                        return TRUE;
                    }
                }
            } else
                DbgLog("  WriteToReadOnly: cannot read page table PA (MmMapIoSpace) — trying kernel VA PTE flip");
        } else
            DbgLog("  WriteToReadOnly: could not resolve PTE/PDE physical address — trying kernel VA PTE flip");
    } else
        DbgLog("  WriteToReadOnly: no verified CR3 from MZ test — trying kernel VA PTE flip");

    /* --- Safe path: scan the running ntoskrnl image for MiGetPteAddress to get PTE_BASE --- */
    {
        ULONG64 pteBase = KM_ScanKernelImageForPteBase();
        if (pteBase) {
            /* Validate PTE_BASE using consecutive PFN check:
               PTEs for g_KernelBase and g_KernelBase+0x1000 must both be present AND
               have consecutive PFNs (adjacent kernel image pages are physically adjacent).
               A single present-bit check is not enough — kernel PE headers start with
               0x4D ('M') which has bit 0 = 1, causing false positives. */
            ULONG64 kbasePte  = pteBase + (((LONG64)(ULONG64)g_KernelBase >> 9) & 0x7FFFFFFFF8);
            ULONG64 kbasePte2 = pteBase + (((LONG64)((ULONG64)g_KernelBase + 0x1000) >> 9) & 0x7FFFFFFFF8);
            ULONG64 kbasePteVal = 0, kbasePteVal2 = 0;
            BOOL valid = KM_IsCanonicalKernelVa(kbasePte) &&
                         KM_IsCanonicalKernelVa(kbasePte2) &&
                         KM_ReadKernelMemory(kbasePte,  &kbasePteVal,  sizeof(kbasePteVal)) &&
                         KM_ReadKernelMemory(kbasePte2, &kbasePteVal2, sizeof(kbasePteVal2)) &&
                         (kbasePteVal & 1) && (kbasePteVal2 & 1) &&
                         /* Consecutive virtual pages must have consecutive PFNs */
                         (((kbasePteVal2 >> 12) & 0xFFFFFFFFFULL) ==
                          ((kbasePteVal  >> 12) & 0xFFFFFFFFFULL) + 1);
            if (valid) {
                DbgLog("  WriteToReadOnly: PTE_BASE=0x%llX (kernel scan, kbasePTE=0x%llX val=0x%llX)",
                    pteBase, kbasePte, kbasePteVal);
                if (KM_TryKernelVaWritableFlip(pteBase, kernelAddr, buffer, size))
                    return TRUE;
                DbgLog("  WriteToReadOnly: kernel PTE_BASE flip inconclusive, continuing");
            } else {
                DbgLog("  WriteToReadOnly: PTE_BASE=0x%llX failed consecutive-PFN validation (p1=0x%llX p2=0x%llX)",
                    pteBase, kbasePteVal, kbasePteVal2);
            }
        } else {
            DbgLog("  WriteToReadOnly: kernel image PTE_BASE scan found no match");
        }
    }

    /*
     * IMPORTANT: do NOT auto-run KM_FindPteBaseForSystem here.
     *
     * An earlier revision of this file tried to fall through to a PML4
     * candidate-index scan automatically on Win11 24H2+ (build 26100+).
     * Issue #6 (majlis1qatar-eng, Apr 2026) reproduced an immediate BSOD
     * exactly at the "trying PML4 candidate-index scan" log line.
     *
     * Why it BSODs on 24H2:
     *   - KM_FindPteBaseForSystem iterates PML4 indices 256..511 and reads
     *     a computed PTE slot for each via Nal case 0x33.
     *   - Nal case 0x33 uses MmCopyMemory(MM_COPY_MEMORY_VIRTUAL), which
     *     handles PTE/PDE-level faults (__try/__except catches them) but
     *     does NOT survive when the PML4 entry itself is non-present --
     *     the hardware walk fails at the top level before the software
     *     fault handler is reachable, and on 24H2 HVCI/KDP this surfaces
     *     as IRQL_NOT_LESS_OR_EQUAL / KERNEL_SECURITY_CHECK_FAILURE.
     *
     * Consequence: on Win11 24H2 with the current kdmapper primitives,
     * we simply cannot discover the KASLR'd PTE_BASE safely. Users see
     * the honest error below. A real fix requires either:
     *   (a) a different vulnerable driver that exposes an arbitrary-read
     *       with __try/__except at PML4 level, or
     *   (b) deriving PTE_BASE from disassembling nt!MiGetPteAddress in
     *       the running kernel image without guessing.
     *
     * The env-var HWID_ALLOW_UNSAFE_KVA_PTE_SCAN=1 is retained so we can
     * re-enable the scan on developer machines for research, but it will
     * stay OFF for shipped builds.
     */
    {
        char v[8] = {0};
        DWORD n = GetEnvironmentVariableA(
            "HWID_ALLOW_UNSAFE_KVA_PTE_SCAN", v, (DWORD)sizeof(v));
        BOOL allow = (n > 0 && n < sizeof(v) &&
            (v[0] == '1' || v[0] == 'y' || v[0] == 'Y' ||
             v[0] == 't' || v[0] == 'T'));
        if (!allow) {
            DbgLog("  WriteToReadOnly: PML4 candidate-index scan disabled "
                "(BSODs on Win11 24H2 per GitHub issue #6). Set "
                "HWID_ALLOW_UNSAFE_KVA_PTE_SCAN=1 only on a lab machine.");
            SetLastMapFailV(
                "Kernel write path aborted. On Windows 11 24H2+ with HVCI / "
                "VBS / KDP, the iqvw64e mapper cannot complete: Intel Nal "
                "MapPhys is restricted and we do not auto-run the "
                "candidate-index PTE_BASE scan (it bugchecks on PML4-not-present "
                "faults — see ISSUES.md section 6 and issue #6). Disable Memory "
                "Integrity, VBS, and the hypervisor (README Setup Guide), "
                "reboot, and retry; or use a different vulnerable driver "
                "(roadmap).");
            return FALSE;
        }
        DbgLog("  WriteToReadOnly: UNSAFE PML4 scan explicitly enabled "
            "via HWID_ALLOW_UNSAFE_KVA_PTE_SCAN");
        ULONG64 pteBase = KM_FindPteBaseForSystem();
        if (!pteBase) {
            DbgLog("  WriteToReadOnly FAIL: PML4 scan found no match");
            SetLastMapFailV(
                "Unsafe PML4 scan enabled but found no PTE_BASE candidate.");
            return FALSE;
        }
        DbgLog("  WriteToReadOnly: using PTE_BASE=0x%llX (candidate-index scan)", pteBase);
        if (KM_TryKernelVaWritableFlip(pteBase, kernelAddr, buffer, size))
            return TRUE;
    }

    DbgLog("  WriteToReadOnly FAIL: physical and kernel-VA PTE/PDE flips both failed");
    return FALSE;
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
        PIMAGE_THUNK_DATA origThunk;
        if (importDesc->OriginalFirstThunk)
            origThunk = (PIMAGE_THUNK_DATA)((BYTE*)imageBase + importDesc->OriginalFirstThunk);
        else
            origThunk = (PIMAGE_THUNK_DATA)((BYTE*)imageBase + importDesc->FirstThunk);
        PIMAGE_THUNK_DATA thunk = (PIMAGE_THUNK_DATA)((BYTE*)imageBase + importDesc->FirstThunk);
        while (origThunk->u1.AddressOfData) {
            if (origThunk->u1.Ordinal & IMAGE_ORDINAL_FLAG64) {
                thunk++;
                origThunk++;
                continue;
            }
            PIMAGE_IMPORT_BY_NAME imp = (PIMAGE_IMPORT_BY_NAME)((BYTE*)imageBase + (origThunk->u1.AddressOfData & 0x7FFFFFFF));
            PVOID funcAddr = KM_GetKernelExport((const char*)imp->Name);
            if (!funcAddr) {
                SetLastMapFailV("Import resolution failed: export \"%s\" not found in ntoskrnl.",
                    imp->Name);
                return FALSE;
            }
            thunk->u1.Function = (ULONG64)funcAddr;
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

/*
 * Scan all loaded kernel modules (via EnumDeviceDrivers) for a section that is
 * both EXECUTABLE and WRITABLE and contains a run of `needed` padding bytes
 * (0x00, 0xCC, or 0x90).  Returns the VA of the start of that run, or 0.
 *
 * Writing shellcode to an ERW region via case 0x33 never requires touching page
 * tables, so it works even on systems where KDP/SLAT protects PTE pages.
 */
static ULONG64 KM_FindExecutableWritableScratch(SIZE_T needed) {
    LPVOID mods[512];
    DWORD cb = 0;
    if (!EnumDeviceDrivers(mods, sizeof(mods), &cb)) return 0;
    DWORD count = cb / sizeof(LPVOID);

    const DWORD CAP = 0x80000; /* 512 KB per section */
    BYTE* buf = (BYTE*)malloc(CAP);
    if (!buf) return 0;
    ULONG64 result = 0;

    DWORD d;
    for (d = 0; d < count && !result; d++) {
        ULONG64 base = (ULONG64)mods[d];
        if (!base) continue;

        BYTE hdr[0x1000];
        if (!KM_ReadKernelMemory(base, hdr, sizeof(hdr))) continue;

        PIMAGE_DOS_HEADER dos = (PIMAGE_DOS_HEADER)hdr;
        if (dos->e_magic != IMAGE_DOS_SIGNATURE) continue;
        if ((DWORD)dos->e_lfanew + sizeof(IMAGE_NT_HEADERS64) > sizeof(hdr)) continue;
        PIMAGE_NT_HEADERS64 nt = (PIMAGE_NT_HEADERS64)(hdr + dos->e_lfanew);
        if (nt->Signature != IMAGE_NT_SIGNATURE) continue;

        PIMAGE_SECTION_HEADER sec = IMAGE_FIRST_SECTION(nt);
        WORD si;
        for (si = 0; si < nt->FileHeader.NumberOfSections && !result; si++) {
            DWORD chars = sec[si].Characteristics;
            if (!(chars & IMAGE_SCN_MEM_EXECUTE)) continue;
            if (!(chars & IMAGE_SCN_MEM_WRITE))   continue;
            if (chars & IMAGE_SCN_MEM_DISCARDABLE) continue;

            ULONG64 secVA = base + sec[si].VirtualAddress;
            DWORD secSize = sec[si].Misc.VirtualSize;
            if (secSize < needed + 16) continue;
            if (secSize > CAP) secSize = CAP;

            if (!KM_ReadKernelMemory(secVA, buf, secSize)) continue;

            SIZE_T run = 0;
            DWORD runStart = 0;
            BYTE runByte = 0;
            DWORD b;
            for (b = 0; b < secSize && !result; b++) {
                BYTE c = buf[b];
                if (run == 0 || c == runByte) {
                    if (run == 0) {
                        if (c != 0x00 && c != 0xCC && c != 0x90) continue;
                        runByte  = c;
                        runStart = b;
                    }
                    if (++run >= needed + 8)
                        result = secVA + runStart;
                } else {
                    run = 0;
                }
            }
        }
    }

    free(buf);
    if (result)
        DbgLog("  ErwScratch: found ERW padding at 0x%llX", result);
    else
        DbgLog("  ErwScratch: no ERW section with sufficient padding found");
    return result;
}

ULONG64 KM_AllocateKernelPool(SIZE_T size) {
    PVOID pExAllocatePool = KM_GetKernelExport("ExAllocatePoolWithTag");
    if (!pExAllocatePool) return 0;

    PVOID halDispatch = KM_GetKernelExport("HalDispatchTable");
    if (!halDispatch) return 0;
    ULONG64 halD1 = (ULONG64)halDispatch + 8;

    HMODULE ntdll = GetModuleHandleA("ntdll.dll");
    if (!ntdll) return 0;
    pNtQueryIntervalProfile NtQIP =
        (pNtQueryIntervalProfile)GetProcAddress(ntdll, "NtQueryIntervalProfile");
    if (!NtQIP) return 0;

    ULONG64 codeCave = KM_FindCodeCave(80);
    if (!codeCave) return 0;

    unsigned char sc[] = {
        0x53,                                           // push rbx
        0x48, 0x83, 0xEC, 0x20,                        // sub rsp, 0x20
        0x48, 0x31, 0xC9,                              // xor rcx, rcx  (NonPagedPool=0, executable)
        0x48, 0xBA,                                     // mov rdx, imm64 (size)
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x49, 0xB8,                                     // mov r8, imm64 (tag)
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x48, 0xB8,                                     // mov rax, imm64 (ExAllocatePoolWithTag)
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0xFF, 0xD0,                                     // call rax
        0x48, 0xBB,                                     // mov rbx, imm64 (HalDispatchTable+8, writable .data)
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
    *(ULONG64*)(sc + 42) = halD1;

    DbgLog("  AllocPool: ExAllocatePool=0x%llX, HalD1=0x%llX, codeCave=0x%llX",
        (ULONG64)pExAllocatePool, halD1, codeCave);

    /* Try ERW scratch first — avoids page-table writes (safe on KDP/SLAT systems).
       Fall back to PTE flip via KM_WriteToReadOnlyMemory if no ERW region exists. */
    DbgLog("  AllocPool: probing for executable+writable scratch region...");
    ULONG64 erw = KM_FindExecutableWritableScratch(sizeof(sc));
    if (erw) {
        DbgLog("  AllocPool: using ERW scratch 0x%llX for shellcode", erw);
        if (!KM_WriteKernelMemory(erw, sc, sizeof(sc))) {
            DbgLog("  AllocPool: ERW scratch write FAILED, falling back to code cave PTE flip");
            erw = 0;
        } else {
            codeCave = erw;
        }
    }
    if (!erw) {
        DbgLog("  AllocPool: writing shellcode to code cave (PTE flip)...");
        if (!KM_WriteToReadOnlyMemory(codeCave, sc, sizeof(sc))) {
            DbgLog("  AllocPool FAIL: could not write shellcode to code cave");
            return 0;
        }
    }
    DbgLog("  AllocPool: shellcode written OK at 0x%llX", codeCave);

    ULONG64 originalFunc = 0;
    if (!KM_ReadKernelMemory(halD1, &originalFunc, sizeof(originalFunc))) {
        DbgLog("  AllocPool FAIL: could not read original HalDispatch[1]");
        return 0;
    }
    DbgLog("  AllocPool: original HalDispatch[1]=0x%llX", originalFunc);

    DbgLog("  AllocPool: patching HalDispatch[1] -> codeCave...");
    if (!KM_WriteKernelMemory(halD1, &codeCave, sizeof(codeCave))) {
        DbgLog("  AllocPool FAIL: could not write HalDispatch[1]");
        return 0;
    }
    DbgLog("  AllocPool: HalDispatch patched, calling NtQueryIntervalProfile...");

    ULONG interval = 0;
    NtQIP(2, &interval);
    DbgLog("  AllocPool: NtQIP returned (survived!)");

    ULONG64 poolAddr = 0;
    KM_ReadKernelMemory(halD1, &poolAddr, sizeof(poolAddr));
    DbgLog("  AllocPool: poolAddr=0x%llX", poolAddr);

    KM_WriteKernelMemory(halD1, &originalFunc, sizeof(originalFunc));
    DbgLog("  AllocPool: HalDispatch[1] restored");

    return poolAddr;
}

BOOL KM_CallDriverEntry(ULONG64 entryAddr) {
    PVOID halDispatch = KM_GetKernelExport("HalDispatchTable");
    if (!halDispatch) return FALSE;
    ULONG64 halD1 = (ULONG64)halDispatch + 8;

    HMODULE ntdll = GetModuleHandleA("ntdll.dll");
    if (!ntdll) return FALSE;
    pNtQueryIntervalProfile NtQIP =
        (pNtQueryIntervalProfile)GetProcAddress(ntdll, "NtQueryIntervalProfile");
    if (!NtQIP) return FALSE;

    ULONG64 codeCave = KM_FindCodeCave(80);
    if (!codeCave) return FALSE;

    unsigned char sc[] = {
        0x53,                                           // push rbx
        0x48, 0x83, 0xEC, 0x20,                        // sub rsp, 0x20
        0x48, 0x31, 0xC9,                              // xor rcx, rcx  (DriverObject=NULL)
        0x48, 0x31, 0xD2,                              // xor rdx, rdx  (RegistryPath=NULL)
        0x48, 0xB8,                                     // mov rax, imm64 (DriverEntry)
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0xFF, 0xD0,                                     // call rax
        0x48, 0xBB,                                     // mov rbx, imm64 (HalDispatchTable+8, writable .data)
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x48, 0x89, 0x03,                              // mov [rbx], rax
        0x48, 0x83, 0xC4, 0x20,                        // add rsp, 0x20
        0x5B,                                           // pop rbx
        0x31, 0xC0,                                     // xor eax, eax
        0xC3                                            // ret
    };

    *(ULONG64*)(sc + 13) = entryAddr;
    *(ULONG64*)(sc + 25) = halD1;

    DbgLog("  CallEntry: entryAddr=0x%llX, codeCave=0x%llX", entryAddr, codeCave);
    DbgLog("  CallEntry: probing for ERW scratch region...");
    ULONG64 erw = KM_FindExecutableWritableScratch(sizeof(sc));
    if (erw) {
        DbgLog("  CallEntry: using ERW scratch 0x%llX", erw);
        if (!KM_WriteKernelMemory(erw, sc, sizeof(sc))) {
            DbgLog("  CallEntry: ERW scratch write FAILED, falling back to PTE flip");
            erw = 0;
        } else {
            codeCave = erw;
        }
    }
    if (!erw) {
        DbgLog("  CallEntry: writing shellcode via PTE flip...");
        if (!KM_WriteToReadOnlyMemory(codeCave, sc, sizeof(sc))) {
            DbgLog("  CallEntry FAIL: could not write shellcode");
            return FALSE;
        }
    }
    DbgLog("  CallEntry: shellcode written OK at 0x%llX", codeCave);

    ULONG64 originalFunc = 0;
    if (!KM_ReadKernelMemory(halD1, &originalFunc, sizeof(originalFunc))) {
        DbgLog("  CallEntry FAIL: could not read HalDispatch[1]");
        return FALSE;
    }
    DbgLog("  CallEntry: original HalDispatch[1]=0x%llX", originalFunc);

    DbgLog("  CallEntry: patching HalDispatch[1] -> codeCave...");
    if (!KM_WriteKernelMemory(halD1, &codeCave, sizeof(codeCave))) {
        DbgLog("  CallEntry FAIL: could not patch HalDispatch[1]");
        return FALSE;
    }
    DbgLog("  CallEntry: calling NtQueryIntervalProfile (THIS IS THE DANGEROUS CALL)...");

    ULONG interval = 0;
    NtQIP(2, &interval);
    DbgLog("  CallEntry: NtQIP returned (survived DriverEntry!)");

    ULONG64 ntStatus = 0;
    KM_ReadKernelMemory(halD1, &ntStatus, sizeof(ntStatus));
    DbgLog("  CallEntry: DriverEntry NTSTATUS=0x%llX", ntStatus);

    KM_WriteKernelMemory(halD1, &originalFunc, sizeof(originalFunc));
    DbgLog("  CallEntry: HalDispatch[1] restored");

    return ((LONG)ntStatus >= 0);
}

static char g_DbgPath[MAX_PATH] = {0};

static void DbgInit() {
    GetModuleFileNameA(NULL, g_DbgPath, MAX_PATH);
    char* slash = strrchr(g_DbgPath, '\\');
    if (slash) *(slash + 1) = 0;
    strcat_s(g_DbgPath, MAX_PATH, "hwid_debug.log");
    DeleteFileA(g_DbgPath);
}

static void DbgLog(const char* fmt, ...) {
    if (!g_DbgPath[0]) DbgInit();
    HANDLE hFile = CreateFileA(g_DbgPath, FILE_APPEND_DATA, FILE_SHARE_READ,
        NULL, OPEN_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    if (hFile == INVALID_HANDLE_VALUE) return;
    char buf[1024];
    SYSTEMTIME st;
    GetLocalTime(&st);
    int pos = sprintf_s(buf, sizeof(buf), "[%02d:%02d:%02d.%03d] ",
        st.wHour, st.wMinute, st.wSecond, st.wMilliseconds);
    va_list ap;
    va_start(ap, fmt);
    pos += vsprintf_s(buf + pos, sizeof(buf) - pos, fmt, ap);
    va_end(ap);
    buf[pos++] = '\r'; buf[pos++] = '\n';
    DWORD written;
    WriteFile(hFile, buf, pos, &written, NULL);
    FlushFileBuffers(hFile);
    CloseHandle(hFile);
}

BOOL KM_MapDriverFromMemory(PVOID fileBuffer, DWORD fileSize) {
    ClearLastMapFail();
    DbgLog("=== KM_MapDriverFromMemory entered ===");
    DbgLog("KernelBase = 0x%llX", (ULONG64)g_KernelBase);
    DbgLog("VulnDriver handle = 0x%llX", (ULONG64)g_hVulnDriver);

    DbgLog("STEP 1: Canary read - reading 2 bytes from KernelBase...");
    USHORT dosSignature = 0;
    BOOL canaryOk = KM_ReadKernelMemory((ULONG64)g_KernelBase, &dosSignature, sizeof(dosSignature));
    DbgLog("STEP 1 result: read=%s, signature=0x%04X (expect 0x5A4D)",
        canaryOk ? "OK" : "FAIL", dosSignature);

    if (!canaryOk || dosSignature != 0x5A4D) {
        SetLastMapFailV(
            "Canary failed: KernelBase=0x%llX read=%s sig=0x%04X (expect MZ). "
            "Bad read: IOCTL 0x33/copy path. Bad sig: wrong kernel base.",
            (ULONG64)g_KernelBase, canaryOk ? "OK" : "FAIL", dosSignature);
        return FALSE;
    }
    DbgLog("STEP 1 PASSED: kernel base is valid, case 0x33 works");

    if (!fileBuffer || fileSize < sizeof(IMAGE_DOS_HEADER)) {
        SetLastMapFailV("Embedded driver resource is missing or too small to be a PE.");
        return FALSE;
    }

    PIMAGE_DOS_HEADER dos = (PIMAGE_DOS_HEADER)fileBuffer;
    PIMAGE_NT_HEADERS64 nt = (PIMAGE_NT_HEADERS64)((BYTE*)fileBuffer + dos->e_lfanew);

    SIZE_T imageSize = nt->OptionalHeader.SizeOfImage;
    DWORD entryRVA = nt->OptionalHeader.AddressOfEntryPoint;

    DbgLog("STEP 2: PE parsed - imageSize=%llu, entryRVA=0x%X", (ULONG64)imageSize, entryRVA);

    PVOID localImage = VirtualAlloc(NULL, imageSize, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (!localImage) {
        DbgLog("STEP 2 FAIL: VirtualAlloc returned NULL");
        SetLastMapFailV("VirtualAlloc for local PE image failed (size %llu).", (ULONG64)imageSize);
        return FALSE;
    }

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
    DbgLog("STEP 2 PASSED: %d sections copied to local image", nt->FileHeader.NumberOfSections);

    DbgLog("STEP 3: Allocating kernel pool (size=%llu)...", (ULONG64)imageSize);
    ULONG64 kernelPool = KM_AllocateKernelPool(imageSize);
    DbgLog("STEP 3 result: kernelPool=0x%llX", kernelPool);
    if (!kernelPool) {
        DbgLog("STEP 3 FAIL: kernel pool allocation returned 0");
        VirtualFree(localImage, 0, MEM_RELEASE);
        SetLastMapFailV("Kernel pool allocation failed (ExAllocatePool shellcode / HalDispatchTable path).");
        return FALSE;
    }
    DbgLog("STEP 3 PASSED: kernel pool at 0x%llX", kernelPool);

    DbgLog("STEP 4: Processing relocations...");
    KM_ProcessRelocations(localImage, (PVOID)kernelPool, imageSize);
    DbgLog("STEP 4 PASSED");

    DbgLog("STEP 5: Resolving imports...");
    if (!KM_ResolveImports(localImage)) {
        DbgLog("STEP 5 FAIL: import resolution failed");
        VirtualFree(localImage, 0, MEM_RELEASE);
        if (!g_LastMapFail[0])
            SetLastMapFailV("Import resolution failed.");
        return FALSE;
    }
    DbgLog("STEP 5 PASSED");

    DbgLog("STEP 6: Writing driver image to kernel pool...");
    KM_WriteKernelMemory(kernelPool, localImage, imageSize);
    DbgLog("STEP 6 PASSED");

    VirtualFree(localImage, 0, MEM_RELEASE);

    DbgLog("STEP 7: Calling DriverEntry at 0x%llX...", kernelPool + entryRVA);
    ULONG64 entryAddr = kernelPool + entryRVA;
    BOOL result = KM_CallDriverEntry(entryAddr);
    DbgLog("STEP 7 result: %s", result ? "SUCCESS" : "FAILED");
    DbgLog("=== Debug log complete - all steps finished ===");

    if (!result)
        SetLastMapFailV("DriverEntry returned failure or shellcode did not run (see NTSTATUS in hwid_debug.log).");
    return result;
}

// ==================== DRIVER MANAGEMENT ====================

BOOL LoadSpooferDriver() {
    DbgInit();
    DbgLog("========================================");
    DbgLog("=== HWID Spoofer Diagnostic Log ===");
    DbgLog("========================================");
    {
        RTL_OSVERSIONINFOW os = {0};
        os.dwOSVersionInfoSize = sizeof(os);
        pRtlGetVersion pRv = (pRtlGetVersion)GetProcAddress(
            GetModuleHandleA("ntdll.dll"), "RtlGetVersion");
        if (pRv && pRv(&os) >= 0) {
            DbgLog("Windows: %lu.%lu build %lu", os.dwMajorVersion, os.dwMinorVersion,
                os.dwBuildNumber);
        } else {
            DbgLog("Windows: RtlGetVersion unavailable or failed");
        }
    }

    DbgLog("STAGE 0: Pre-flight environment checks...");
    if (!PreFlight_Check(g_VulnDriverPath)) {
        DbgLog("STAGE 0 FAIL: pre-flight rejected environment");
        char msg[768];
        sprintf_s(msg, sizeof(msg),
            "Pre-flight check failed.\n\n%s\n\n"
            "Full log: hwid_debug.log next to Manager.exe",
            g_LastMapFail[0] ? g_LastMapFail
                             : "No detail available (see log).");
        MessageBoxA(g_hWnd, msg,
            "Driver Error - Pre-flight", MB_ICONERROR);
        return FALSE;
    }
    DbgLog("STAGE 0 PASSED: pre-flight OK");

    DbgLog("STAGE 1: Loading vulnerable driver...");
    if (!LoadVulnerableDriver()) {
        DWORD err = GetLastError();
        DbgLog("STAGE 1 FAIL: err=%lu", err);
        char msg[512];
        sprintf_s(msg, sizeof(msg),
            "Stage 1 failed: vulnerable driver won't load.\n"
            "Error code: %lu\n\n"
            "- Disable Memory Integrity in Windows Security\n"
            "- Disable Vulnerable Driver Blocklist (registry)\n"
            "- Reboot after changing settings\n\n"
            "Debug log: same folder as Manager.exe", err);
        MessageBoxA(g_hWnd, msg, "Driver Error - Stage 1", MB_ICONERROR);
        return FALSE;
    }
    DbgLog("STAGE 1 PASSED: vulnerable driver loaded");

    DbgLog("STAGE 2: Getting kernel base...");
    g_KernelBase = KM_GetKernelBase();
    if (!g_KernelBase) {
        DbgLog("STAGE 2 FAIL: KM_GetKernelBase returned NULL");
        MessageBoxA(g_hWnd, "Stage 2 failed: cannot locate kernel base address.",
            "Driver Error - Stage 2", MB_ICONERROR);
        UnloadVulnerableDriver();
        return FALSE;
    }
    DbgLog("STAGE 2 PASSED: KernelBase=0x%llX", (ULONG64)g_KernelBase);

    DbgLog("STAGE 3: Loading spoofer driver resource...");
    HRSRC hRes = FindResourceA(g_hInst, MAKEINTRESOURCEA(IDR_SPOOFER_SYS), RT_RCDATA);
    if (!hRes) {
        DbgLog("STAGE 3 FAIL: FindResourceA returned NULL");
        MessageBoxA(g_hWnd, "Stage 3 failed: spoofer driver resource not found in EXE.",
            "Driver Error - Stage 3", MB_ICONERROR);
        UnloadVulnerableDriver();
        return FALSE;
    }

    HGLOBAL hData = LoadResource(g_hInst, hRes);
    DWORD resSize = SizeofResource(g_hInst, hRes);
    PVOID resData = hData ? LockResource(hData) : NULL;
    if (!resData || resSize == 0) {
        DbgLog("STAGE 3 FAIL: resource data NULL or size 0");
        MessageBoxA(g_hWnd, "Stage 3 failed: cannot read spoofer driver resource.",
            "Driver Error - Stage 3", MB_ICONERROR);
        UnloadVulnerableDriver();
        return FALSE;
    }
    DbgLog("STAGE 3 PASSED: resource size=%lu bytes", resSize);

    DbgLog("STAGE 4: Mapping spoofer driver into kernel...");
    if (!KM_MapDriverFromMemory(resData, resSize)) {
        DbgLog("STAGE 4 FAIL: KM_MapDriverFromMemory returned FALSE");
        {
            char msg[1536];
            sprintf_s(msg, sizeof(msg),
                "Stage 4 failed: kernel mapping did not complete.\n\n"
                "Windows 11 24H2 (build 26100+): there is no silent fallback "
                "that magically finds PTE_BASE — unsafe scans are opt-in only "
                "(ISSUES.md). With HVCI/VBS on, the iqvw64e path is blocked.\n\n"
                "%s\n\n"
                "Full step log: hwid_debug.log next to Manager.exe",
                g_LastMapFail[0] ? g_LastMapFail
                    : "No detail (see log for steps 1/3/5/7).");
            MessageBoxA(g_hWnd, msg, "Driver Error - Stage 4", MB_ICONERROR);
        }
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

