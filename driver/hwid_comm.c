/*
 * hwid_comm.c - Driver-side communication module implementation.
 *
 * Responsibilities:
 *   - Own the global HWID_SHARED_BLOCK (magic/version/size/status/log)
 *   - Publish the block to a disk-backed shared file so the manager can
 *     consume it with a single ReadFile + magic/version check.
 *   - Create the named revert event used by the manager to request revert.
 *
 * This keeps HelloWorld.c (hooks / spoof) free of protocol plumbing.
 */

#include "hwid_comm.h"

NTSYSCALLAPI NTSTATUS NTAPI ZwCreateEvent(
    PHANDLE EventHandle, ACCESS_MASK DesiredAccess,
    POBJECT_ATTRIBUTES ObjectAttributes, EVENT_TYPE EventType,
    BOOLEAN InitialState);

/* The single shared-block instance. */
HWID_SHARED_BLOCK g_HwidShared = { 0 };

VOID HwidComm_Init(VOID)
{
    RtlZeroMemory(&g_HwidShared, sizeof(g_HwidShared));
    g_HwidShared.magic   = HWID_PROTOCOL_MAGIC;
    g_HwidShared.version = HWID_PROTOCOL_VERSION;
    g_HwidShared.size    = (unsigned int)sizeof(HWID_SHARED_BLOCK);
    g_HwidShared.status  = HWID_STATUS_INIT;
    g_HwidShared.command = HWID_CMD_NONE;
}

VOID HwidComm_SetStatus(unsigned int status)
{
    g_HwidShared.status = status;
}

static BOOLEAN HwidCommpWriteFile(PCWSTR Path)
{
    UNICODE_STRING fp;
    OBJECT_ATTRIBUTES oa;
    IO_STATUS_BLOCK io;
    HANDLE hf;
    NTSTATUS st;

    RtlInitUnicodeString(&fp, Path);
    InitializeObjectAttributes(&oa, &fp,
        OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE, NULL, NULL);

    st = ZwCreateFile(&hf,
        GENERIC_WRITE | SYNCHRONIZE, &oa, &io, NULL,
        FILE_ATTRIBUTE_HIDDEN | FILE_ATTRIBUTE_SYSTEM,
        0, FILE_OVERWRITE_IF,
        FILE_SYNCHRONOUS_IO_NONALERT, NULL, 0);
    if (!NT_SUCCESS(st))
        return FALSE;

    st = ZwWriteFile(hf, NULL, NULL, NULL, &io,
        &g_HwidShared, sizeof(g_HwidShared), NULL, NULL);
    ZwClose(hf);
    return NT_SUCCESS(st);
}

BOOLEAN HwidComm_Publish(VOID)
{
    /* Always refresh the 3 invariant fields in case caller zeroed them. */
    g_HwidShared.magic   = HWID_PROTOCOL_MAGIC;
    g_HwidShared.version = HWID_PROTOCOL_VERSION;
    g_HwidShared.size    = (unsigned int)sizeof(HWID_SHARED_BLOCK);

    if (HwidCommpWriteFile(HWID_SHARED_FILE_PRIMARY_W))
        return TRUE;

    return HwidCommpWriteFile(HWID_SHARED_FILE_FALLBACK_W);
}

NTSTATUS HwidComm_CreateRevertEvent(PKEVENT* OutEvent)
{
    UNICODE_STRING evtName;
    OBJECT_ATTRIBUTES evtOa;
    HANDLE hEvt;
    NTSTATUS st;
    PKEVENT ev = NULL;
    SECURITY_DESCRIPTOR sd;

    if (!OutEvent)
        return STATUS_INVALID_PARAMETER;
    *OutEvent = NULL;

    /*
     * Build a NULL-DACL security descriptor: grants full access to every
     * caller. Without this, the event ends up with the default kernel
     * security descriptor and user-mode OpenEvent() silently fails with
     * ACCESS_DENIED, which was the root cause of the manager "revert has
     * no effect" reports. NULL DACL is acceptable here - this is a
     * signalling primitive, not a secret.
     */
    st = RtlCreateSecurityDescriptor(&sd, SECURITY_DESCRIPTOR_REVISION);
    if (!NT_SUCCESS(st))
        return st;
    st = RtlSetDaclSecurityDescriptor(&sd, TRUE /* DaclPresent */,
        NULL /* NULL DACL = everyone */, FALSE /* not defaulted */);
    if (!NT_SUCCESS(st))
        return st;

    RtlInitUnicodeString(&evtName, HWID_REVERT_EVENT_NAME_W);
    InitializeObjectAttributes(&evtOa, &evtName,
        OBJ_CASE_INSENSITIVE, NULL, &sd);

    st = ZwCreateEvent(&hEvt, EVENT_ALL_ACCESS, &evtOa,
        NotificationEvent, FALSE);
    if (!NT_SUCCESS(st))
        return st;

    st = ObReferenceObjectByHandle(hEvt, EVENT_ALL_ACCESS,
        *ExEventObjectType, KernelMode, (PVOID*)&ev, NULL);
    ZwClose(hEvt);

    if (!NT_SUCCESS(st) || !ev)
        return NT_SUCCESS(st) ? STATUS_UNSUCCESSFUL : st;

    KeClearEvent(ev);
    *OutEvent = ev;
    return STATUS_SUCCESS;
}
