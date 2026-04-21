/*
 * pte_comm.h - PTE-based stealthy driver communication.
 *
 * Hooks NtQueryCompositionSurfaceStatistics in dxgkrnl.sys via PTE
 * manipulation. Usermode calls this function with a specially crafted
 * buffer; if magic matches, the driver processes the command. Otherwise,
 * the original function executes normally.
 *
 * PASSTHROUGH DESIGN:
 * For non-hooked calls, we cannot call into a page *copy* because dxgkrnl
 * code contains RIP-relative instructions that reference addresses relative
 * to the original VA. Calling from a different VA would produce wrong
 * targets for LEA, CALL, MOV [rip+disp], etc.
 *
 * Instead, we temporarily swap the PTE back to the original PFN, call the
 * function at its real VA (where all RIP-relative addresses are correct),
 * then swap back to the shadow. A per-CPU recursion guard prevents
 * re-entry during the brief original-PTE window.
 */

#ifndef HWID_PTE_COMM_H
#define HWID_PTE_COMM_H

#include <ntifs.h>
#include <ntimage.h>
#include <intrin.h>
#include "../shared/hwid_protocol.h"

/* ----------------------------------------------------------------
 * Communication protocol structures
 * ---------------------------------------------------------------- */

#define PTE_COMM_MAGIC  0x44524B4Eu  /* "DRKN" */

typedef enum _PTE_COMM_CMD {
    PTE_CMD_PING         = 0x01,
    PTE_CMD_GET_LOG      = 0x02,
    PTE_CMD_GET_STATUS   = 0x03,
    PTE_CMD_REVERT       = 0x04,
} PTE_COMM_CMD;

/* Request buffer passed from usermode */
typedef struct _PTE_COMM_REQUEST {
    unsigned int    magic;       /* must be PTE_COMM_MAGIC */
    unsigned int    command;     /* PTE_COMM_CMD */
    unsigned int    status_out;  /* filled by driver */
    unsigned int    reserved;
    HWID_SHARED_BLOCK block_out; /* filled for GET_LOG/GET_STATUS */
} PTE_COMM_REQUEST;

/* ----------------------------------------------------------------
 * PTE type
 * ---------------------------------------------------------------- */

typedef union _PTE_CONTENTS {
    ULONG64 Value;
    struct {
        ULONG64 Present       : 1;
        ULONG64 Write         : 1;
        ULONG64 User          : 1;
        ULONG64 WriteThrough  : 1;
        ULONG64 CacheDisable  : 1;
        ULONG64 Accessed      : 1;
        ULONG64 Dirty         : 1;
        ULONG64 LargePage     : 1;
        ULONG64 Global        : 1;
        ULONG64 CopyOnWrite   : 1;
        ULONG64 Prototype     : 1;
        ULONG64 Reserved0     : 1;
        ULONG64 PageFrameNumber : 36;
        ULONG64 Reserved1     : 16;
    };
} PTE_CONTENTS;

/* ----------------------------------------------------------------
 * Globals
 * ---------------------------------------------------------------- */

static PVOID   g_PteShadowPage   = NULL;   /* shadow page with our hook JMP */
static PVOID   g_PteHookTarget   = NULL;   /* VA of hooked function */
static ULONG64 g_PteOrigValue    = 0;      /* original PTE value */
static ULONG64 g_PteShadowValue  = 0;      /* shadow PTE value (cached) */
static PVOID   g_PtePteAddress   = NULL;   /* PTE address for the hooked page */
static PVOID   g_PtePageBase     = NULL;   /* page-aligned base of hook target */
static BOOLEAN g_PteHookActive   = FALSE;

/* Recursion guard for passthrough PTE swap (interlocked, 0=free 1=busy) */
static volatile LONG g_PtePassthroughBusy = 0;

typedef NTSTATUS (NTAPI *FnNtQueryCompSurfStats)(PVOID, PVOID, ULONG);

/* These globals must be defined in the including translation unit:
 *   HWID_SHARED_BLOCK g_HwidShared;   (from hwid_comm.h / hwid_comm.c)
 *   PKEVENT g_pRevertEvent;            (from HelloWorld.c)
 * Since this is a header-only module included directly in HelloWorld.c,
 * both are already visible at the point of inclusion. */

/* ----------------------------------------------------------------
 * MiGetPteAddress resolver
 * ---------------------------------------------------------------- */

typedef PVOID (*FnMiGetPteAddress)(PVOID);
static FnMiGetPteAddress g_MiGetPteAddress = NULL;

static BOOLEAN PteComm_ResolveMiGetPte(PVOID kernelBase) {
    PIMAGE_DOS_HEADER dos = (PIMAGE_DOS_HEADER)kernelBase;
    if (dos->e_magic != IMAGE_DOS_SIGNATURE) return FALSE;

    PIMAGE_NT_HEADERS64 nt = (PIMAGE_NT_HEADERS64)(
        (PUCHAR)kernelBase + dos->e_lfanew);
    if (nt->Signature != IMAGE_NT_SIGNATURE) return FALSE;

    PIMAGE_SECTION_HEADER sec = IMAGE_FIRST_SECTION(nt);

    for (USHORT i = 0; i < nt->FileHeader.NumberOfSections; i++) {
        if (sec[i].Name[0] != '.' || sec[i].Name[1] != 't') continue;

        PUCHAR start = (PUCHAR)kernelBase + sec[i].VirtualAddress;
        SIZE_T size = sec[i].Misc.VirtualSize;

        /*
         * MiGetPteAddress pattern (31 bytes total):
         * 48 C1 E9 09 48 B8 F8 FF FF FF 7F 00 00 00
         * 48 23 C8 48 B8 [8 bytes PTE_BASE]
         * 48 03 C1 C3
         */
        static const UCHAR pat[] = {
            0x48, 0xC1, 0xE9, 0x09,
            0x48, 0xB8, 0xF8, 0xFF, 0xFF, 0xFF, 0x7F, 0x00, 0x00, 0x00,
            0x48, 0x23, 0xC8,
            0x48, 0xB8
        };
        const SIZE_T totalLen = sizeof(pat) + 8 + 4; /* pat + PTE_BASE + tail */

        if (size < totalLen) continue;

        for (SIZE_T j = 0; j <= size - totalLen; j++) {
            BOOLEAN match = TRUE;
            for (SIZE_T k = 0; k < sizeof(pat); k++) {
                if (start[j + k] != pat[k]) { match = FALSE; break; }
            }
            if (match &&
                start[j + sizeof(pat) + 8]  == 0x48 &&
                start[j + sizeof(pat) + 9]  == 0x03 &&
                start[j + sizeof(pat) + 10] == 0xC1 &&
                start[j + sizeof(pat) + 11] == 0xC3) {
                g_MiGetPteAddress = (FnMiGetPteAddress)&start[j];
                return TRUE;
            }
        }
    }
    return FALSE;
}

/* ----------------------------------------------------------------
 * Find NtQueryCompositionSurfaceStatistics in dxgkrnl.sys
 * ---------------------------------------------------------------- */

/* ZwQuerySystemInformation and RTL_PROCESS_MODULE* types are declared
 * in cleaner.h which must be included before this header. */

NTKERNELAPI PVOID NTAPI RtlFindExportedRoutineByName(PVOID, PCCH);

static PVOID PteComm_FindDxgkrnlExport(const char* exportName) {
    ULONG needed = 0;
    ZwQuerySystemInformation(11, NULL, 0, &needed);
    if (!needed) return NULL;

    PVOID buf = ExAllocatePool2(POOL_FLAG_NON_PAGED, needed, 'xgDK');
    if (!buf) return NULL;

    if (!NT_SUCCESS(ZwQuerySystemInformation(11, buf, needed, &needed))) {
        ExFreePoolWithTag(buf, 'xgDK');
        return NULL;
    }

    RTL_PROCESS_MODULES* mods = (RTL_PROCESS_MODULES*)buf;
    PVOID dxgBase = NULL;

    for (ULONG i = 0; i < mods->NumberOfModules; i++) {
        char* name = &mods->Modules[i].FullPathName[mods->Modules[i].OffsetToFileName];
        if (_stricmp(name, "dxgkrnl.sys") == 0) {
            dxgBase = mods->Modules[i].ImageBase;
            break;
        }
    }
    ExFreePoolWithTag(buf, 'xgDK');

    if (!dxgBase) return NULL;
    return RtlFindExportedRoutineByName(dxgBase, exportName);
}

/* ----------------------------------------------------------------
 * Hook handler
 * ---------------------------------------------------------------- */

static NTSTATUS NTAPI PteComm_HookHandler(
    PVOID arg1, PVOID arg2, ULONG arg3)
{
    /* Check if this is our communication request */
    __try {
        PTE_COMM_REQUEST* req = (PTE_COMM_REQUEST*)arg1;
        if (req && req->magic == PTE_COMM_MAGIC) {
            switch (req->command) {
            case PTE_CMD_PING:
                req->status_out = HWID_STATUS_READY;
                break;

            case PTE_CMD_GET_LOG:
            case PTE_CMD_GET_STATUS:
                RtlCopyMemory(&req->block_out, &g_HwidShared,
                    sizeof(HWID_SHARED_BLOCK));
                req->status_out = g_HwidShared.status;
                break;

            case PTE_CMD_REVERT:
                if (g_pRevertEvent)
                    KeSetEvent(g_pRevertEvent, IO_NO_INCREMENT, FALSE);
                req->status_out = HWID_STATUS_REVERTING;
                break;

            default:
                req->status_out = HWID_STATUS_FAILED;
                break;
            }
            return STATUS_SUCCESS;
        }
    } __except (EXCEPTION_EXECUTE_HANDLER) { }

    /*
     * Not our request — passthrough to the real function.
     *
     * We temporarily swap the PTE back to the original PFN so the CPU
     * executes the real dxgkrnl code at its correct VA (preserving all
     * RIP-relative addressing). Then swap back to the shadow.
     *
     * Recursion guard: if another thread/CPU is already in passthrough
     * (PTE is temporarily original), calling the same VA would hit the
     * real function directly — that's actually correct, no infinite loop.
     * But if WE are re-entered somehow, the CAS prevents stack overflow.
     */
    if (!g_PteHookActive || !g_PtePteAddress)
        return STATUS_NOT_IMPLEMENTED;

    if (InterlockedCompareExchange(&g_PtePassthroughBusy, 1, 0) != 0) {
        /* Already in passthrough — another thread owns it.
         * The PTE is currently pointing to original, so calling at the
         * real VA would execute the real function. Just do that. */
        FnNtQueryCompSurfStats fn = (FnNtQueryCompSurfStats)g_PteHookTarget;
        return fn(arg1, arg2, arg3);
    }

    PTE_CONTENTS* pte = (PTE_CONTENTS*)g_PtePteAddress;

    /* Restore original PTE (this CPU only; other CPUs hitting the hook
     * during this window will enter the handler → see passthrough busy
     * → call the real function at its original VA, which is correct
     * since we've restored the PTE on this CPU). */
    _disable();
    pte->Value = g_PteOrigValue;
    __invlpg(g_PtePageBase);
    _enable();

    /* Call the original function at its real VA */
    FnNtQueryCompSurfStats origFn = (FnNtQueryCompSurfStats)g_PteHookTarget;
    NTSTATUS result = origFn(arg1, arg2, arg3);

    /* Re-install shadow PTE */
    _disable();
    pte->Value = g_PteShadowValue;
    __invlpg(g_PtePageBase);
    _enable();

    InterlockedExchange(&g_PtePassthroughBusy, 0);
    return result;
}

/* ----------------------------------------------------------------
 * PTE Hook Install / Remove
 * ---------------------------------------------------------------- */

/* IPI callback to flush TLB on all processors */
static ULONG_PTR PteComm_FlushTlbIpi(ULONG_PTR arg) {
    __invlpg((PVOID)arg);
    return 0;
}

static BOOLEAN PteComm_Install(PVOID kernelBase) {
    if (!PteComm_ResolveMiGetPte(kernelBase))
        return FALSE;

    /* Find the target function */
    g_PteHookTarget = PteComm_FindDxgkrnlExport(
        "NtQueryCompositionSurfaceStatistics");
    if (!g_PteHookTarget)
        return FALSE;

    g_PtePageBase = (PVOID)((ULONG_PTR)g_PteHookTarget & ~0xFFF);

    /* Get PTE for the target page */
    g_PtePteAddress = g_MiGetPteAddress(g_PteHookTarget);
    if (!g_PtePteAddress)
        return FALSE;

    PTE_CONTENTS* pte = (PTE_CONTENTS*)g_PtePteAddress;
    g_PteOrigValue = pte->Value;

    /*
     * Allocate shadow page with MmAllocateContiguousMemory:
     *  - Guarantees page-aligned, physically contiguous memory
     *  - Required because we swap PFN in the PTE; pool allocations
     *    have headers and are NOT page-aligned
     */
    PHYSICAL_ADDRESS maxAddr;
    maxAddr.QuadPart = MAXULONG64;

    g_PteShadowPage = MmAllocateContiguousMemory(PAGE_SIZE, maxAddr);
    if (!g_PteShadowPage)
        return FALSE;

    /* Copy original page content to shadow */
    RtlCopyMemory(g_PteShadowPage, g_PtePageBase, PAGE_SIZE);

    /* Calculate offset of target function within the page */
    ULONG offset = (ULONG)((ULONG_PTR)g_PteHookTarget & 0xFFF);

    /* Patch shadow page: write a 14-byte absolute jmp to our handler
     *   FF 25 00000000    jmp qword ptr [rip+0]
     *   <8 bytes>         handler address
     */
    PUCHAR hookSite = (PUCHAR)g_PteShadowPage + offset;
    hookSite[0] = 0xFF;
    hookSite[1] = 0x25;
    *(ULONG*)&hookSite[2] = 0;
    *(PVOID*)&hookSite[6] = (PVOID)PteComm_HookHandler;

    /* Build and cache the shadow PTE value */
    PHYSICAL_ADDRESS physAddr = MmGetPhysicalAddress(g_PteShadowPage);
    PTE_CONTENTS newPte;
    newPte.Value = g_PteOrigValue;
    newPte.PageFrameNumber = (physAddr.QuadPart >> 12);
    g_PteShadowValue = newPte.Value;

    /* Swap PTE and flush TLB on ALL processors */
    _disable();
    pte->Value = g_PteShadowValue;
    _enable();
    KeIpiGenericCall(PteComm_FlushTlbIpi, (ULONG_PTR)g_PtePageBase);

    g_PteHookActive = TRUE;
    return TRUE;
}

static VOID PteComm_Remove(void) {
    if (!g_PteHookActive || !g_PtePteAddress)
        return;

    /* Wait for any in-flight passthrough to finish */
    while (InterlockedCompareExchange(&g_PtePassthroughBusy, 1, 0) != 0)
        _mm_pause();

    PTE_CONTENTS* pte = (PTE_CONTENTS*)g_PtePteAddress;

    /* Restore original PTE and flush TLB on all CPUs */
    _disable();
    pte->Value = g_PteOrigValue;
    _enable();
    KeIpiGenericCall(PteComm_FlushTlbIpi, (ULONG_PTR)g_PtePageBase);

    g_PteHookActive = FALSE;
    InterlockedExchange(&g_PtePassthroughBusy, 0);

    /* Brief delay to let any in-flight calls through the hook JMP
     * finish before we free the shadow page they might reference. */
    LARGE_INTEGER delay;
    delay.QuadPart = -(LONGLONG)(50 * 10000); /* 50ms */
    KeDelayExecutionThread(KernelMode, FALSE, &delay);

    if (g_PteShadowPage) {
        MmFreeContiguousMemory(g_PteShadowPage);
        g_PteShadowPage = NULL;
    }
}

#endif /* HWID_PTE_COMM_H */
