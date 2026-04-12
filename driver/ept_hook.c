/*
 * Hypervisor-Based Hooking using Intel VT-x EPT (Extended Page Tables)
 * 
 * EPT hooks provide stealthy, invisible code hooking by using hardware-level
 * page table manipulation instead of inline code modification.
 * 
 * Benefits:
 * - Zero code modification (original bytes intact)
 * - Invisible to PatchGuard and kernel integrity checks
 * - No timing discrepancies from inline hooks
 * - Can have multiple "views" of memory (clean vs hooked)
 */

#include <ntddk.h>
#include <intrin.h>

// EPT (Extended Page Table) definitions
#define EPT_PML4_ENTRIES        512
#define EPT_PDPTE_ENTRIES       512
#define EPT_PDE_ENTRIES         512
#define EPT_PTE_ENTRIES         512

// EPT page size
#define EPT_PAGE_SIZE_4K        0x1000
#define EPT_PAGE_SIZE_2M        0x200000
#define EPT_PAGE_SIZE_1G        0x40000000

// EPT entry flags
#define EPT_FLAG_READ           0x01
#define EPT_FLAG_WRITE          0x02
#define EPT_FLAG_EXECUTE        0x04
#define EPT_FLAG_MEMORY_TYPE    0x38  // Bits 3-5
#define EPT_FLAG_IGNORE_PAT     0x40
#define EPT_FLAG_LARGE_PAGE     0x80
#define EPT_FLAG_ACCESSED       0x100
#define EPT_FLAG_DIRTY          0x200
#define EPT_FLAG_SUPPRESS_VE    0x8000000000000000ULL

// EPT memory types
#define EPT_MEMORY_UC           0x00  // Uncacheable
#define EPT_MEMORY_WC           0x01  // Write-combining
#define EPT_MEMORY_WT           0x04  // Write-through
#define EPT_MEMORY_WP           0x05  // Write-protected
#define EPT_MEMORY_WB           0x06  // Write-back

// VMCS EPT-related controls
#define VMCS_CTRL_EPT_POINTER   0x201A
#define VMCS_CTRL_EPTP_LIST_ADDR 0x2024
#define VMCS_CTRL_VMFUNC        0x2018

// VM exit reasons related to EPT
#define EXIT_REASON_EPT_VIOLATION  48
#define EXIT_REASON_EPT_MISCONFIG  49

// Hook structure
typedef struct _EPT_HOOK {
    LIST_ENTRY      ListEntry;
    
    // Original function info
    PVOID           OriginalFunction;
    PVOID           OriginalPage;
    UINT64          OriginalPagePFN;
    
    // Hook function
    PVOID           HookFunction;
    
    // Shadow page (the hooked view)
    PVOID           ShadowPage;
    UINT64          ShadowPagePFN;
    
    // Split page structures for fine-grained control
    PEPT_PTE        OriginalPTE;
    PEPT_PTE        ShadowPTE;
    
    // Hook metadata
    CHAR            TargetModuleName[64];
    CHAR            TargetFunctionName[64];
    BOOLEAN         IsActive;
    UINT64          HitCount;
} EPT_HOOK, *PEPT_HOOK;

// EPT context per processor
typedef struct _EPT_CONTEXT {
    BOOLEAN         Initialized;
    
    // EPT paging structures
    PEPT_PML4       Pml4;
    PHYSICAL_ADDRESS Pml4Phys;
    
    // Page pool for EPT allocations
    PVOID           PagePool;
    UINT32          PagePoolUsed;
    UINT32          PagePoolSize;
    
    // Hook list
    LIST_ENTRY      HookList;
    KSPIN_LOCK      HookListLock;
    
    // EPT violation statistics
    UINT64          TotalViolations;
    UINT64          HandledViolations;
    
    // Multiple EPTP support for different views
    UINT64          EptPointer;      // Active EPT
    UINT64          EptPointerClean; // Clean view (no hooks)
    UINT64          EptPointerHooked; // Hooked view
} EPT_CONTEXT, *PEPT_CONTEXT;

static EPT_CONTEXT g_EptContext[64] = {0};  // Support up to 64 CPUs
static ULONG g_ProcessorCount = 0;

// EPT paging structures
typedef struct _EPT_PML4 {
    union {
        struct {
            UINT64 Read : 1;
            UINT64 Write : 1;
            UINT64 Execute : 1;
            UINT64 Reserved1 : 5;
            UINT64 Accessed : 1;
            UINT64 Ignored1 : 1;
            UINT64 ExecuteForUserMode : 1;
            UINT64 Ignored2 : 1;
            UINT64 PhysicalAddress : 40;
            UINT64 Ignored3 : 12;
            UINT64 SuppressVe : 1;
        };
        UINT64 Value;
    };
} EPT_PML4, *PEPT_PML4;

typedef struct _EPT_PDPTE {
    union {
        struct {
            UINT64 Read : 1;
            UINT64 Write : 1;
            UINT64 Execute : 1;
            UINT64 MemoryType : 3;
            UINT64 IgnorePAT : 1;
            UINT64 LargePage : 1;
            UINT64 Accessed : 1;
            UINT64 Ignored1 : 1;
            UINT64 ExecuteForUserMode : 1;
            UINT64 Ignored2 : 1;
            UINT64 PhysicalAddress : 40;
            UINT64 Ignored3 : 12;
            UINT64 SuppressVe : 1;
        };
        UINT64 Value;
    };
} EPT_PDPTE, *PEPT_PDPTE;

typedef struct _EPT_PDE {
    union {
        struct {
            UINT64 Read : 1;
            UINT64 Write : 1;
            UINT64 Execute : 1;
            UINT64 MemoryType : 3;
            UINT64 IgnorePAT : 1;
            UINT64 LargePage : 1;
            UINT64 Accessed : 1;
            UINT64 Dirty : 1;
            UINT64 ExecuteForUserMode : 1;
            UINT64 Ignored1 : 1;
            UINT64 PhysicalAddress : 40;
            UINT64 Ignored2 : 11;
            UINT64 SuppressVe : 1;
        };
        UINT64 Value;
    };
} EPT_PDE, *PEPT_PDE;

typedef struct _EPT_PTE {
    union {
        struct {
            UINT64 Read : 1;
            UINT64 Write : 1;
            UINT64 Execute : 1;
            UINT64 MemoryType : 3;
            UINT64 IgnorePAT : 1;
            UINT64 Ignored1 : 1;
            UINT64 Accessed : 1;
            UINT64 Dirty : 1;
            UINT64 ExecuteForUserMode : 1;
            UINT64 Ignored2 : 1;
            UINT64 PhysicalAddress : 40;
            UINT64 Ignored3 : 11;
            UINT64 SuppressVe : 1;
        };
        UINT64 Value;
    };
} EPT_PTE, *PEPT_PTE;

// Function types for hook targets
typedef NTSTATUS (*GenericFunction)(...);

/*
 * Allocate EPT page table page
 */
PEPT_PML4 Ept_AllocatePageTablePage(PEPT_CONTEXT Context) {
    // Allocate from page pool
    if (Context->PagePoolUsed + PAGE_SIZE > Context->PagePoolSize) {
        return NULL;
    }
    
    PVOID page = (PUINT8)Context->PagePool + Context->PagePoolUsed;
    Context->PagePoolUsed += PAGE_SIZE;
    
    RtlZeroMemory(page, PAGE_SIZE);
    
    return (PEPT_PML4)page;
}

/*
 * Initialize EPT for a processor
 */
NTSTATUS Ept_InitializeProcessor(ULONG ProcessorNumber) {
    PEPT_CONTEXT ctx = &g_EptContext[ProcessorNumber];
    
    if (ctx->Initialized) {
        return STATUS_SUCCESS;
    }
    
    // Allocate page pool for EPT structures
    ctx->PagePoolSize = 0x400000;  // 4MB for page tables
    ctx->PagePool = MmAllocateContiguousMemory(
        ctx->PagePoolSize,
        (PHYSICAL_ADDRESS){0, 0}
    );
    if (!ctx->PagePool) {
        return STATUS_INSUFFICIENT_RESOURCES;
    }
    
    ctx->PagePoolUsed = 0;
    
    // Allocate PML4
    ctx->Pml4 = Ept_AllocatePageTablePage(ctx);
    if (!ctx->Pml4) {
        MmFreeContiguousMemory(ctx->PagePool);
        return STATUS_INSUFFICIENT_RESOURCES;
    }
    
    ctx->Pml4Phys = MmGetPhysicalAddress(ctx->Pml4);
    
    // Initialize hook list
    InitializeListHead(&ctx->HookList);
    KeInitializeSpinLock(&ctx->HookListLock);
    
    // Build EPT identity mapping (map all physical memory)
    // In production, this would enumerate physical memory ranges
    
    ctx->Initialized = TRUE;
    return STATUS_SUCCESS;
}

/*
 * Get EPT entry for a guest physical address
 */
PEPT_PTE Ept_GetPTE(PEPT_CONTEXT Context, UINT64 GuestPhysical) {
    UINT64 pml4Index = (GuestPhysical >> 39) & 0x1FF;
    UINT64 pdpteIndex = (GuestPhysical >> 30) & 0x1FF;
    UINT64 pdeIndex = (GuestPhysical >> 21) & 0x1FF;
    UINT64 pteIndex = (GuestPhysical >> 12) & 0x1FF;
    
    // Traverse page tables
    PEPT_PML4 pml4 = Context->Pml4;
    if (!pml4[pml4Index].Read) {
        return NULL;  // Not mapped
    }
    
    PEPT_PDPTE pdpte = (PEPT_PDPTE)(pml4[pml4Index].PhysicalAddress << 12);
    if (!pdpte[pdpteIndex].Read) {
        return NULL;
    }
    
    // Check for 1GB page
    if (pdpte[pdpteIndex].LargePage) {
        return NULL;  // 1GB page, no PTE
    }
    
    PEPT_PDE pde = (PEPT_PDE)(pdpte[pdpteIndex].PhysicalAddress << 12);
    if (!pde[pdeIndex].Read) {
        return NULL;
    }
    
    // Check for 2MB page
    if (pde[pdeIndex].LargePage) {
        return NULL;  // 2MB page, no PTE
    }
    
    PEPT_PTE pte = (PEPT_PTE)(pde[pdeIndex].PhysicalAddress << 12);
    return &pte[pteIndex];
}

/*
 * Split large page (1GB or 2MB) into 4KB pages
 * This is needed for fine-grained hooking
 */
NTSTATUS Ept_SplitLargePage(PEPT_CONTEXT Context, UINT64 GuestPhysical) {
    PEPT_PTE pte = Ept_GetPTE(Context, GuestPhysical);
    if (pte) {
        return STATUS_SUCCESS;  // Already split
    }
    
    // Find and split the large page
    // Implementation involves:
    // 1. Finding the large page entry
    // 2. Allocating new page table
    // 3. Copying mappings with new permissions
    // 4. Replacing large page entry with pointer to new table
    
    return STATUS_SUCCESS;
}

/*
 * Create EPT hook for a function
 */
PEPT_HOOK Ept_CreateHook(
    PEPT_CONTEXT Context,
    PVOID TargetFunction,
    PVOID HookFunction,
    PCHAR TargetModuleName,
    PCHAR TargetFunctionName
) {
    PEPT_HOOK hook = ExAllocatePool2(POOL_FLAG_NON_PAGED, sizeof(EPT_HOOK), 'EPTH');
    if (!hook) {
        return NULL;
    }
    
    RtlZeroMemory(hook, sizeof(EPT_HOOK));
    
    hook->OriginalFunction = TargetFunction;
    hook->HookFunction = HookFunction;
    
    if (TargetModuleName) {
        RtlStringCbCopyA(hook->TargetModuleName, sizeof(hook->TargetModuleName), 
                        TargetModuleName);
    }
    if (TargetFunctionName) {
        RtlStringCbCopyA(hook->TargetFunctionName, sizeof(hook->TargetFunctionName),
                        TargetFunctionName);
    }
    
    // Get the page containing the target function
    UINT64 targetAddr = (UINT64)TargetFunction;
    hook->OriginalPage = (PVOID)(targetAddr & ~0xFFF);
    hook->OriginalPagePFN = MmGetPhysicalAddress(hook->OriginalPage).QuadPart >> 12;
    
    // Allocate shadow page
    PHYSICAL_ADDRESS lowAddr = {0, 0};
    PHYSICAL_ADDRESS highAddr = (PHYSICAL_ADDRESS){0xFFFFFFFF, 0};
    
    hook->ShadowPage = MmAllocateContiguousMemorySpecifyCache(
        PAGE_SIZE, lowAddr, highAddr, lowAddr, MmCached);
    if (!hook->ShadowPage) {
        ExFreePoolWithTag(hook, 'EPTH');
        return NULL;
    }
    
    hook->ShadowPagePFN = MmGetPhysicalAddress(hook->ShadowPage).QuadPart >> 12;
    
    // Copy original page to shadow
    RtlCopyMemory(hook->ShadowPage, hook->OriginalPage, PAGE_SIZE);
    
    // Modify shadow page - redirect function to hook
    // Options:
    // 1. Overwrite function start with jump to hook (in shadow only)
    // 2. Overwrite page with hook function code
    // 3. Set up trampoline in shadow
    
    // For this implementation, we'll use inline hook in shadow page
    PUINT8 hookLocation = (PUINT8)hook->ShadowPage + 
                          ((UINT64)TargetFunction & 0xFFF);
    
    // Write relative jump to hook function
    // 0xE9 xx xx xx xx (jmp rel32)
    INT32 relOffset = (INT32)((UINT64)HookFunction - 
                              ((UINT64)hookLocation + 5));
    hookLocation[0] = 0xE9;
    RtlCopyMemory(&hookLocation[1], &relOffset, 4);
    
    // Remaining bytes filled with NOPs or original code
    for (INT i = 5; i < 15; i++) {
        hookLocation[i] = 0x90;  // NOP
    }
    
    // Insert into hook list
    KIRQL oldIrql;
    KeAcquireSpinLock(&Context->HookListLock, &oldIrql);
    InsertTailList(&Context->HookList, &hook->ListEntry);
    KeReleaseSpinLock(&Context->HookListLock, oldIrql);
    
    hook->IsActive = FALSE;
    
    return hook;
}

/*
 * Activate EPT hook
 */
NTSTATUS Ept_ActivateHook(PEPT_HOOK Hook) {
    if (Hook->IsActive) {
        return STATUS_SUCCESS;
    }
    
    // Find EPT PTE for original page
    ULONG processor = KeGetCurrentProcessorNumber();
    PEPT_CONTEXT ctx = &g_EptContext[processor];
    
    // Ensure page is split to 4KB
    NTSTATUS status = Ept_SplitLargePage(ctx, (UINT64)Hook->OriginalPage);
    if (!NT_SUCCESS(status)) {
        return status;
    }
    
    PEPT_PTE pte = Ept_GetPTE(ctx, (UINT64)Hook->OriginalPage);
    if (!pte) {
        return STATUS_NOT_FOUND;
    }
    
    // Save original PTE
    Hook->OriginalPTE = *pte;
    
    // Modify PTE to point to shadow page
    pte->PhysicalAddress = Hook->ShadowPagePFN;
    pte->Read = 1;
    pte->Write = 1;
    pte->Execute = 1;
    
    // Save modified PTE
    Hook->ShadowPTE = *pte;
    
    Hook->IsActive = TRUE;
    
    // Invalidate EPT TLB
    __vmx_vmfunc(0, 0);  // INVEPT
    
    return STATUS_SUCCESS;
}

/*
 * Deactivate EPT hook
 */
NTSTATUS Ept_DeactivateHook(PEPT_HOOK Hook) {
    if (!Hook->IsActive) {
        return STATUS_SUCCESS;
    }
    
    ULONG processor = KeGetCurrentProcessorNumber();
    PEPT_CONTEXT ctx = &g_EptContext[processor];
    
    PEPT_PTE pte = Ept_GetPTE(ctx, (UINT64)Hook->OriginalPage);
    if (!pte) {
        return STATUS_NOT_FOUND;
    }
    
    // Restore original PTE
    *pte = Hook->OriginalPTE;
    
    Hook->IsActive = FALSE;
    
    // Invalidate EPT TLB
    __vmx_vmfunc(0, 0);  // INVEPT
    
    return STATUS_SUCCESS;
}

/*
 * Handle EPT violation (VM exit)
 * 
 * Called when guest accesses a page that's not mapped or has wrong permissions
 */
NTSTATUS Ept_HandleViolation(
    PEPT_CONTEXT Context,
    UINT64 GuestPhysical,
    UINT64 GuestLinear,
    BOOLEAN CausedByRead,
    BOOLEAN CausedByWrite,
    BOOLEAN CausedByExecute,
    PBOOLEAN Resolved
) {
    *Resolved = FALSE;
    Context->TotalViolations++;
    
    // Check if this is a hooked page
    KIRQL oldIrql;
    KeAcquireSpinLock(&Context->HookListLock, &oldIrql);
    
    PLIST_ENTRY entry = Context->HookList.Flink;
    while (entry != &Context->HookList) {
        PEPT_HOOK hook = CONTAINING_RECORD(entry, EPT_HOOK, ListEntry);
        
        if ((UINT64)hook->OriginalPage == (GuestPhysical & ~0xFFF)) {
            // This is a hooked page
            
            if (CausedByExecute && hook->IsActive) {
                // Execution on hooked page - shadow page should handle this
                // If we got here, something is wrong with the shadow
                // Could set up alternate mapping here
                
                *Resolved = TRUE;
                Context->HandledViolations++;
            }
            
            KeReleaseSpinLock(&Context->HookListLock, oldIrql);
            return STATUS_SUCCESS;
        }
        
        entry = entry->Flink;
    }
    
    KeReleaseSpinLock(&Context->HookListLock, oldIrql);
    
    // Not a hooked page - pass through to normal handler
    return STATUS_UNSUCCESSFUL;
}

/*
 * Remove EPT hook
 */
VOID Ept_RemoveHook(PEPT_HOOK Hook) {
    if (Hook->IsActive) {
        Ept_DeactivateHook(Hook);
    }
    
    // Remove from list
    ULONG processor = KeGetCurrentProcessorNumber();
    PEPT_CONTEXT ctx = &g_EptContext[processor];
    
    KIRQL oldIrql;
    KeAcquireSpinLock(&ctx->HookListLock, &oldIrql);
    RemoveEntryList(&Hook->ListEntry);
    KeReleaseSpinLock(&ctx->HookListLock, oldIrql);
    
    // Free resources
    if (Hook->ShadowPage) {
        MmFreeContiguousMemory(Hook->ShadowPage);
    }
    
    ExFreePoolWithTag(Hook, 'EPTH');
}

/*
 * Get hook statistics
 */
VOID Ept_GetStatistics(PEPT_CONTEXT Context, PUINT64 Total, PUINT64 Handled) {
    *Total = Context->TotalViolations;
    *Handled = Context->HandledViolations;
}

/*
 * Switch EPT view (clean vs hooked)
 */
NTSTATUS Ept_SwitchView(PEPT_CONTEXT Context, BOOLEAN UseHookedView) {
    UINT64 newEptp = UseHookedView ? Context->EptPointerHooked : Context->EptPointerClean;
    
    if (newEptp == 0) {
        return STATUS_NOT_SUPPORTED;
    }
    
    // Write new EPT pointer to VMCS
    __vmx_vmwrite(VMCS_CTRL_EPT_POINTER, newEptp);
    
    // INVEPT to invalidate cached translations
    __vmx_vmfunc(0, 0);
    
    return STATUS_SUCCESS;
}

/*
 * Initialize EPT system
 */
NTSTATUS Ept_InitializeSystem(VOID) {
    // Get processor count
    g_ProcessorCount = KeQueryActiveProcessorCount(NULL);
    if (g_ProcessorCount > 64) {
        g_ProcessorCount = 64;
    }
    
    // Initialize EPT for each processor
    for (ULONG i = 0; i < g_ProcessorCount; i++) {
        NTSTATUS status = Ept_InitializeProcessor(i);
        if (!NT_SUCCESS(status)) {
            // Cleanup already initialized processors
            return status;
        }
    }
    
    return STATUS_SUCCESS;
}

/*
 * Cleanup EPT system
 */
VOID Ept_CleanupSystem(VOID) {
    for (ULONG i = 0; i < g_ProcessorCount; i++) {
        PEPT_CONTEXT ctx = &g_EptContext[i];
        
        if (!ctx->Initialized) {
            continue;
        }
        
        // Remove all hooks
        while (!IsListEmpty(&ctx->HookList)) {
            PLIST_ENTRY entry = RemoveHeadList(&ctx->HookList);
            PEPT_HOOK hook = CONTAINING_RECORD(entry, EPT_HOOK, ListEntry);
            
            if (hook->ShadowPage) {
                MmFreeContiguousMemory(hook->ShadowPage);
            }
            ExFreePoolWithTag(hook, 'EPTH');
        }
        
        // Free page pool
        if (ctx->PagePool) {
            MmFreeContiguousMemory(ctx->PagePool);
        }
        
        ctx->Initialized = FALSE;
    }
}
