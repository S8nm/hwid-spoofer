/*
 * hwid_comm.h - User-mode driver communication wrapper (DriverComm).
 *
 * Centralizes all interaction with the HWID spoofer driver:
 *   - Init()                : locate + open the shared-block file, handshake
 *                             (magic + version + size), set connected state.
 *   - IsConnected()         : fast status query for UI.
 *   - Ping()                : re-read shared block, update cached copy.
 *   - GetLog()              : return pointer to the cached HWID_ID_LOG.
 *   - GetStatus()           : return last known HWID_STATUS.
 *   - RequestRevert()       : signal the named revert event.
 *   - Shutdown()            : release resources, delete stale shared file.
 *
 * Pattern mirrors External_Rust_AI/NullKD User/driver_comm.h: one class-like
 * object wrapping all comm, typed accessors, explicit handshake and fail-fast
 * on version mismatch, error telemetry at every stage (via DbgLog callback).
 */

#ifndef HWID_MANAGER_COMM_H
#define HWID_MANAGER_COMM_H

#include <windows.h>
#include "../shared/hwid_protocol.h"

#ifdef __cplusplus
extern "C" {
#endif

/* ---- PTE hook comm protocol (mirrors driver/pte_comm.h) ---- */

#define PTE_COMM_MAGIC  0x44524B4Eu  /* "DRKN" */

typedef enum _PTE_COMM_CMD {
    PTE_CMD_PING         = 0x01,
    PTE_CMD_GET_LOG      = 0x02,
    PTE_CMD_GET_STATUS   = 0x03,
    PTE_CMD_REVERT       = 0x04,
} PTE_COMM_CMD;

typedef struct _PTE_COMM_REQUEST {
    unsigned int    magic;
    unsigned int    command;
    unsigned int    status_out;
    unsigned int    reserved;
    HWID_SHARED_BLOCK block_out;
} PTE_COMM_REQUEST;

/* Log sink installed by the manager (DbgLog in manager.c). NULL = silent. */
typedef void (*HwidCommLogFn)(const char* fmt, ...);

/* Opaque-ish state; kept in header so manager globals can embed it. */
typedef struct _HWID_DRIVER_COMM {
    HWID_SHARED_BLOCK cached;       /* last successfully read block */
    BOOL              connected;    /* handshake succeeded */
    BOOL              usePteComm;   /* TRUE if PTE hook channel is active */
    DWORD             lastError;    /* Win32 error from last failed op */
    HwidCommLogFn     logFn;        /* telemetry sink, may be NULL */
    FARPROC           pteFunc;      /* NtQueryCompositionSurfaceStatistics */
} HWID_DRIVER_COMM;

/* Initialise comm, install optional log sink. Call once at startup. */
void HwidComm_Create(HWID_DRIVER_COMM* c, HwidCommLogFn logFn);

/*
 * Handshake with the driver:
 *   - Polls primary + fallback shared-block files for up to timeoutMs.
 *   - Validates magic / version / size; any mismatch => fail-fast (no partial
 *     data trusted).
 *   - On success, populates c->cached and sets c->connected = TRUE.
 * Returns TRUE only when fully connected.
 */
BOOL HwidComm_Init(HWID_DRIVER_COMM* c, DWORD timeoutMs);

/* Re-reads the shared block (useful for status polling). Returns TRUE on
 * successful read + validation. */
BOOL HwidComm_Refresh(HWID_DRIVER_COMM* c);

/* Convenience accessors. Safe to call before Init (return defaults). */
BOOL                    HwidComm_IsConnected(const HWID_DRIVER_COMM* c);
const HWID_ID_LOG*      HwidComm_GetLog(const HWID_DRIVER_COMM* c);
unsigned int            HwidComm_GetStatus(const HWID_DRIVER_COMM* c);

/* Signal the driver to revert via the named event. Returns TRUE on set. */
BOOL HwidComm_RequestRevert(HWID_DRIVER_COMM* c);

/*
 * Poll the shared block until status == HWID_STATUS_REVERTED or timeoutMs
 * elapses. Returns TRUE only on confirmed revert (safe to unload driver).
 * Must be called AFTER HwidComm_RequestRevert so the driver has started
 * the revert path. Polls at 100ms intervals.
 */
BOOL HwidComm_WaitForRevert(HWID_DRIVER_COMM* c, DWORD timeoutMs);

/* Tear-down: forgets state, deletes the on-disk shared block files. */
void HwidComm_Shutdown(HWID_DRIVER_COMM* c);

#ifdef __cplusplus
}
#endif

#endif /* HWID_MANAGER_COMM_H */
