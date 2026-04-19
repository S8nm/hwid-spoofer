/*
 * hwid_protocol.h - Shared protocol between HWID spoofer driver and manager.
 *
 * Included by:
 *   driver/  (kernel, C)  - populates the shared block
 *   manager/ (user,   C)  - reads the shared block via DriverComm wrapper
 *
 * Pattern adapted from External_Rust_AI/NullKD/shared.h:
 *   - single source of truth for struct layout + command IDs
 *   - magic value guards against stale/foreign data
 *   - version field enables forward/backward checks (fail-fast on mismatch)
 *
 * Uses only types available in both kernel and user mode (no windows.h / ntddk.h
 * types). CHAR/UCHAR/ULONG are all plain integer typedefs provided by both SDKs,
 * but we use C99 stdint names here to be independent.
 */

#ifndef HWID_PROTOCOL_H
#define HWID_PROTOCOL_H

#ifdef __cplusplus
extern "C" {
#endif

/* ---------------------------------------------------------------- *
 * Identity / versioning
 * ---------------------------------------------------------------- */

/* ASCII "HWSP" - distinguishes our shared block from arbitrary data.
 * Kept as 4-byte integer (not a string) so there is no null-terminator
 * ambiguity (the old code compared 7 of 8 bytes of "HWIDLOG\0"). */
#define HWID_PROTOCOL_MAGIC   0x50535748u  /* 'H''W''S''P' little-endian */

/* Bump whenever HWID_SHARED_BLOCK layout changes. Manager MUST fail-fast
 * if driver version != manager version. */
#define HWID_PROTOCOL_VERSION 1u

/* Named objects exposed by the driver to user mode.
 * Driver creates in \BaseNamedObjects\... ; manager opens as Global\... */
#define HWID_REVERT_EVENT_NAME_A "Global\\HWIDSpooferRevert"
#define HWID_REVERT_EVENT_NAME_W L"\\BaseNamedObjects\\HWIDSpooferRevert"

/* File-based shared block path (fallback when no named section is set up).
 * Driver writes; manager reads. Manager verifies magic + version before use. */
#define HWID_SHARED_FILE_PRIMARY_A   "C:\\ProgramData\\hwid_shared.bin"
#define HWID_SHARED_FILE_PRIMARY_W   L"\\??\\C:\\ProgramData\\hwid_shared.bin"
#define HWID_SHARED_FILE_FALLBACK_A  "C:\\Windows\\Temp\\hwid_shared.bin"
#define HWID_SHARED_FILE_FALLBACK_W  L"\\??\\C:\\Windows\\Temp\\hwid_shared.bin"

/* ---------------------------------------------------------------- *
 * Commands / status (driver writes command/status, manager polls)
 *
 * Currently only a subset is used (PING for handshake, REVERT request).
 * Enumerated so the protocol is extensible without struct changes.
 * ---------------------------------------------------------------- */

typedef enum _HWID_COMMAND {
    HWID_CMD_NONE        = 0,
    HWID_CMD_PING        = 1,  /* manager handshake -> driver acks via status */
    HWID_CMD_REVERT      = 2,  /* manager requests revert */
    HWID_CMD_REFRESH_LOG = 3,  /* manager asks driver to re-publish log */
} HWID_COMMAND;

typedef enum _HWID_STATUS {
    HWID_STATUS_INIT        = 0,
    HWID_STATUS_READY       = 0x50544548u, /* 'HTEP' - driver fully initialized */
    HWID_STATUS_REVERTING   = 0x52455654u, /* 'REVT' */
    HWID_STATUS_REVERTED    = 0x444F4E45u, /* 'DONE' */
    HWID_STATUS_FAILED      = 0x4641494Cu, /* 'FAIL' */
} HWID_STATUS;

/* ---------------------------------------------------------------- *
 * ID log (original + spoofed hardware identifiers).
 * Mirrors the previous IDLOG/HWID_LOG layout, relocated here so both
 * sides include the *same* definition.
 *
 * NOTE: width fields are fixed (unsigned 8/32 bit) to guarantee both
 * kernel and user mode agree on sizes regardless of SDK.
 * ---------------------------------------------------------------- */

#pragma pack(push, 1)

typedef struct _HWID_ID_LOG {
    char  OrigDiskSerial[64];
    char  FakeDiskSerial[64];

    char  OrigBIOSSerial[64];
    char  FakeBIOSSerial[64];

    char  OrigBoardSerial[64];
    char  FakeBoardSerial[64];

    char  OrigSystemUUID[48];
    char  FakeSystemUUID[48];

    unsigned char  OrigMAC[6];
    unsigned char  FakeMAC[6];

    unsigned int   OrigVolumeSerial;
    unsigned int   FakeVolumeSerial;

    char  OrigGPUId[64];
    char  FakeGPUId[64];

    char  OrigModelNumber[48];
    char  FakeModelNumber[48];

    char  OrigFirmwareRev[16];
    char  FakeFirmwareRev[16];

    char  OrigSmbBoardSerial[64]; /* SMBIOS Type 2 original (pre-spoof) */
} HWID_ID_LOG;

/* ---------------------------------------------------------------- *
 * Shared block - the single payload the driver publishes.
 *
 * Field ordering (fixed for protocol version 1):
 *   magic     : must equal HWID_PROTOCOL_MAGIC
 *   version   : must equal HWID_PROTOCOL_VERSION
 *   size      : sizeof(HWID_SHARED_BLOCK) - sanity check
 *   status    : HWID_STATUS value set by driver
 *   command   : HWID_COMMAND the manager requests (polled by driver)
 *   flags     : reserved / future
 *   log       : populated HWID_ID_LOG
 *
 * The manager MUST validate magic AND version AND size before trusting
 * any other field. This is the "fail fast if handshake/version mismatch"
 * pattern from the NullKD review.
 * ---------------------------------------------------------------- */

typedef struct _HWID_SHARED_BLOCK {
    unsigned int   magic;    /* HWID_PROTOCOL_MAGIC */
    unsigned int   version;  /* HWID_PROTOCOL_VERSION */
    unsigned int   size;     /* sizeof(HWID_SHARED_BLOCK) */
    unsigned int   status;   /* HWID_STATUS */
    unsigned int   command;  /* HWID_COMMAND - manager -> driver */
    unsigned int   flags;    /* reserved */
    unsigned int   reserved[2];
    HWID_ID_LOG    log;
} HWID_SHARED_BLOCK;

#pragma pack(pop)

#ifdef __cplusplus
} /* extern "C" */
#endif

#endif /* HWID_PROTOCOL_H */
