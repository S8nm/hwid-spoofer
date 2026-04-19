/*
 * hwid_comm.h - Driver-side communication module.
 *
 * Isolates the comm layer (status/log publishing + revert event) from
 * the hook/spoof logic. Pattern adapted from NullKD where driver.cpp is
 * small and delegates to focused modules.
 */

#ifndef HWID_DRIVER_COMM_H
#define HWID_DRIVER_COMM_H

/* ntifs.h is a superset of ntddk.h and defines SECURITY_DESCRIPTOR for
 * RtlCreateSecurityDescriptor / InitializeObjectAttributes(..., &sd). */
#include <ntifs.h>
#include "../shared/hwid_protocol.h"

/* Global shared block - exactly one instance owned by the driver.
 * Populated before publishing; also mirrors command state the manager
 * wants executed (currently used only for log payload, revert stays
 * on the named event path). */
extern HWID_SHARED_BLOCK g_HwidShared;

/* Initialize shared block (sets magic/version/size/status = INIT). */
VOID HwidComm_Init(VOID);

/* Set current status (HWID_STATUS_*). */
VOID HwidComm_SetStatus(unsigned int status);

/* Publish current g_HwidShared to disk-backed shared file so user mode
 * can read it. Writes primary path first, falls back to Windows\Temp.
 * Returns TRUE on success. Safe to call multiple times (overwrite). */
BOOLEAN HwidComm_Publish(VOID);

/* Create the named revert event (HWID_REVERT_EVENT_NAME_W). Returns a
 * referenced KEVENT pointer in *OutEvent (caller must ObDereference when
 * done) or NULL on failure. */
NTSTATUS HwidComm_CreateRevertEvent(PKEVENT* OutEvent);

#endif /* HWID_DRIVER_COMM_H */
