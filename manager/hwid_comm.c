/*
 * hwid_comm.c - User-mode DriverComm wrapper implementation.
 *
 * Each stage logs via the injected HwidCommLogFn so a single tail of the
 * manager debug log tells the full story (handshake, version, revert signal).
 */

#include "hwid_comm.h"

#include <stdio.h>

#define HWIDCOMM_LOG(c, fmt, ...) \
    do { if ((c) && (c)->logFn) (c)->logFn(fmt, ##__VA_ARGS__); } while (0)

/* ---------------- internal helpers ---------------- */

static BOOL HwidCommpReadFile(const char* path, HWID_SHARED_BLOCK* out) {
    HANDLE h = CreateFileA(path, GENERIC_READ, FILE_SHARE_READ,
        NULL, OPEN_EXISTING, 0, NULL);
    if (h == INVALID_HANDLE_VALUE)
        return FALSE;

    DWORD read = 0;
    BOOL ok = ReadFile(h, out, sizeof(*out), &read, NULL);
    CloseHandle(h);
    return ok && read == sizeof(*out);
}

static BOOL HwidCommpValidate(HWID_DRIVER_COMM* c, const HWID_SHARED_BLOCK* b) {
    if (b->magic != HWID_PROTOCOL_MAGIC) {
        HWIDCOMM_LOG(c, "HwidComm: MAGIC mismatch (got 0x%08X expected 0x%08X)",
            b->magic, HWID_PROTOCOL_MAGIC);
        return FALSE;
    }
    if (b->version != HWID_PROTOCOL_VERSION) {
        HWIDCOMM_LOG(c, "HwidComm: VERSION mismatch (driver=%u manager=%u) - fail fast",
            b->version, HWID_PROTOCOL_VERSION);
        return FALSE;
    }
    if (b->size != (unsigned int)sizeof(HWID_SHARED_BLOCK)) {
        HWIDCOMM_LOG(c, "HwidComm: SIZE mismatch (driver=%u manager=%zu)",
            b->size, sizeof(HWID_SHARED_BLOCK));
        return FALSE;
    }
    return TRUE;
}

static BOOL HwidCommpReadAndValidate(HWID_DRIVER_COMM* c) {
    HWID_SHARED_BLOCK tmp;
    ZeroMemory(&tmp, sizeof(tmp));

    if (HwidCommpReadFile(HWID_SHARED_FILE_PRIMARY_A, &tmp)) {
        if (HwidCommpValidate(c, &tmp)) {
            c->cached = tmp;
            return TRUE;
        }
    } else {
        c->lastError = GetLastError();
    }

    if (HwidCommpReadFile(HWID_SHARED_FILE_FALLBACK_A, &tmp)) {
        if (HwidCommpValidate(c, &tmp)) {
            c->cached = tmp;
            return TRUE;
        }
    } else {
        c->lastError = GetLastError();
    }

    return FALSE;
}

/* ---------------- public API ---------------- */

void HwidComm_Create(HWID_DRIVER_COMM* c, HwidCommLogFn logFn) {
    if (!c) return;
    ZeroMemory(c, sizeof(*c));
    c->logFn = logFn;
}

BOOL HwidComm_Init(HWID_DRIVER_COMM* c, DWORD timeoutMs) {
    if (!c) return FALSE;

    HWIDCOMM_LOG(c, "HwidComm_Init: starting handshake (timeout=%lums)", timeoutMs);

    const DWORD pollMs = 100;
    DWORD waited = 0;
    for (;;) {
        if (HwidCommpReadAndValidate(c)) {
            c->connected = TRUE;
            HWIDCOMM_LOG(c,
                "HwidComm_Init: CONNECTED magic=0x%08X version=%u status=0x%08X",
                c->cached.magic, c->cached.version, c->cached.status);
            return TRUE;
        }
        if (waited >= timeoutMs)
            break;
        Sleep(pollMs);
        waited += pollMs;
    }

    HWIDCOMM_LOG(c,
        "HwidComm_Init: FAILED after %lums (lastError=%lu) - driver not responding",
        waited, c->lastError);
    c->connected = FALSE;
    return FALSE;
}

BOOL HwidComm_Refresh(HWID_DRIVER_COMM* c) {
    if (!c) return FALSE;
    BOOL ok = HwidCommpReadAndValidate(c);
    if (!ok)
        HWIDCOMM_LOG(c, "HwidComm_Refresh: failed (lastError=%lu)", c->lastError);
    return ok;
}

BOOL HwidComm_IsConnected(const HWID_DRIVER_COMM* c) {
    return c && c->connected;
}

const HWID_ID_LOG* HwidComm_GetLog(const HWID_DRIVER_COMM* c) {
    return c ? &c->cached.log : NULL;
}

unsigned int HwidComm_GetStatus(const HWID_DRIVER_COMM* c) {
    return c ? c->cached.status : HWID_STATUS_INIT;
}

BOOL HwidComm_RequestRevert(HWID_DRIVER_COMM* c) {
    HANDLE hEvt = OpenEventA(EVENT_MODIFY_STATE, FALSE, HWID_REVERT_EVENT_NAME_A);
    if (!hEvt) {
        DWORD err = GetLastError();
        if (c) c->lastError = err;
        HWIDCOMM_LOG(c, "HwidComm_RequestRevert: OpenEvent failed (err=%lu)", err);
        return FALSE;
    }
    BOOL ok = SetEvent(hEvt);
    CloseHandle(hEvt);
    HWIDCOMM_LOG(c, "HwidComm_RequestRevert: %s", ok ? "signalled" : "SetEvent FAILED");
    return ok;
}

BOOL HwidComm_WaitForRevert(HWID_DRIVER_COMM* c, DWORD timeoutMs) {
    if (!c) return FALSE;

    const DWORD pollMs = 100;
    DWORD waited = 0;
    for (;;) {
        if (HwidCommpReadAndValidate(c)) {
            if (c->cached.status == HWID_STATUS_REVERTED) {
                HWIDCOMM_LOG(c, "HwidComm_WaitForRevert: driver confirmed REVERTED after %lums", waited);
                return TRUE;
            }
        }
        if (waited >= timeoutMs)
            break;
        Sleep(pollMs);
        waited += pollMs;
    }
    HWIDCOMM_LOG(c,
        "HwidComm_WaitForRevert: TIMEOUT after %lums (last status=0x%08X) - unloading anyway",
        waited, c->cached.status);
    return FALSE;
}

void HwidComm_Shutdown(HWID_DRIVER_COMM* c) {
    if (!c) return;
    DeleteFileA(HWID_SHARED_FILE_PRIMARY_A);
    DeleteFileA(HWID_SHARED_FILE_FALLBACK_A);
    /* Also clean up legacy file from older driver builds. */
    DeleteFileA("C:\\ProgramData\\hwid_log.bin");
    c->connected = FALSE;
}
