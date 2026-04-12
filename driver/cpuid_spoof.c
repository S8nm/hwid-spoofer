/*
 * CPUID Spoofing - Hypervisor-based CPUID Interception
 * 
 * Uses Intel VT-x/AMD-V to intercept CPUID instructions and return
 * synthetic processor identification information.
 */

#include <ntddk.h>
#include <intrin.h>

// VMX (Intel VT-x) definitions
#define VMX_BASIC_MSR           0x480
#define VMX_CR0_FIXED0_MSR      0x486
#define VMX_CR0_FIXED1_MSR      0x487
#define VMX_CR4_FIXED0_MSR      0x488
#define VMX_CR4_FIXED1_MSR      0x489
#define VMX_VMCS_ENUM_MSR       0x48A

// VMCS (Virtual Machine Control Structure) fields
#define VMCS_CTRL_PIN_BASED     0x4000
#define VMCS_CTRL_PROC_BASED    0x4002
#define VMCS_CTRL_EXIT_REASON   0x4402
#define VMCS_CTRL_ENTRY_CONTROLS 0x4012
#define VMCS_GUEST_RIP          0x681E
#define VMCS_GUEST_RFLAGS       0x6820
#define VMCS_GUEST_RSP          0x681C

// CPUID exit reason
#define EXIT_REASON_CPUID       10

// VMX instructions
#define VMX_ENABLE()            __vmx_on(&g_VmxOnRegionPhys)
#define VMX_DISABLE()           __vmx_off()
#define VMX_VMCLEAR(addr)       __vmclear(addr)
#define VMX_VMPTRLD(addr)       __vmptrld(addr)
#define VMX_VMREAD(field, val)  __vmx_vmread(field, val)
#define VMX_VMWRITE(field, val) __vmx_vmwrite(field, val)
#define VMX_VMLAUNCH()          __vmx_vmlaunch()
#define VMX_VMRESUME()          __vmx_vmresume()

// Context for CPUID spoofing
typedef struct _CPUID_SPOOF_CONTEXT {
    BOOLEAN         VmxEnabled;
    BOOLEAN         SpoofingEnabled;
    
    // VMX regions
    PVOID           VmxOnRegion;
    PHYSICAL_ADDRESS VmxOnRegionPhys;
    PVOID           VmcsRegion;
    PHYSICAL_ADDRESS VmcsRegionPhys;
    PVOID           VmmStack;
    
    // CPUID spoof values
    struct {
        UINT32  VendorEbx;
        UINT32  VendorEdx;
        UINT32  VendorEcx;
        CHAR    BrandString[48];
        UINT32  Family;
        UINT32  Model;
        UINT32  Stepping;
        UINT32  FeaturesEcx;
        UINT32  FeaturesEdx;
        UINT64  ProcessorSerial;
    } FakeCpu;
    
    // Original values
    BOOLEAN         HaveOriginal;
    struct {
        UINT32  VendorEbx;
        UINT32  VendorEdx;
        UINT32  VendorEcx;
        CHAR    BrandString[48];
        UINT32  Family;
        UINT32  Model;
        UINT32  Stepping;
        UINT32  FeaturesEcx;
        UINT32  FeaturesEdx;
    } OriginalCpu;
    
    KSPIN_LOCK      Lock;
} CPUID_SPOOF_CONTEXT;

static CPUID_SPOOF_CONTEXT g_CpuidContext = {0};

/*
 * Check if CPU supports VMX
 */
BOOLEAN CpuidSpoof_CheckVmxSupport(VOID) {
    int cpuInfo[4];
    
    // Check CPUID.1:ECX[5] for VMX support
    __cpuid(cpuInfo, 1);
    if (!(cpuInfo[2] & (1 << 5))) {
        return FALSE;
    }
    
    // Check BIOS lock bit - VMX must be enabled in BIOS
    UINT64 featureControl = __readmsr(0x3A);  // IA32_FEATURE_CONTROL
    if (!(featureControl & 1)) {
        return FALSE;  // BIOS hasn't locked feature control MSR
    }
    if (!(featureControl & 4)) {
        return FALSE;  // VMX outside SMX disabled
    }
    
    return TRUE;
}

/*
 * Enable VMX operation
 */
NTSTATUS CpuidSpoof_EnableVmx(VOID) {
    if (!CpuidSpoof_CheckVmxSupport()) {
        return STATUS_NOT_SUPPORTED;
    }
    
    // Allocate VMXON region (4KB, 4KB aligned)
    g_CpuidContext.VmxOnRegion = MmAllocateContiguousMemory(
        PAGE_SIZE, 
        (PHYSICAL_ADDRESS){0, 0}
    );
    if (!g_CpuidContext.VmxOnRegion) {
        return STATUS_INSUFFICIENT_RESOURCES;
    }
    
    g_CpuidContext.VmxOnRegionPhys = MmGetPhysicalAddress(g_CpuidContext.VmxOnRegion);
    RtlZeroMemory(g_CpuidContext.VmxOnRegion, PAGE_SIZE);
    
    // Get VMX revision identifier
    UINT64 vmxBasic = __readmsr(VMX_BASIC_MSR);
    UINT32 revision = (UINT32)vmxBasic;
    *(UINT32*)g_CpuidContext.VmxOnRegion = revision;
    
    // Set CR4.VMXE bit
    UINT64 cr4 = __readcr4();
    cr4 |= (1 << 13);  // CR4.VMXE
    __writecr4(cr4);
    
    // Set fixed bits in CR0
    UINT64 cr0Fixed0 = __readmsr(VMX_CR0_FIXED0_MSR);
    UINT64 cr0Fixed1 = __readmsr(VMX_CR0_FIXED1_MSR);
    UINT64 cr0 = __readcr0();
    cr0 |= cr0Fixed0;
    cr0 &= cr0Fixed1;
    __writecr0(cr0);
    
    // Execute VMXON
    UINT8 error = (UINT8)VMX_ENABLE();
    if (error != 0) {
        MmFreeContiguousMemory(g_CpuidContext.VmxOnRegion);
        g_CpuidContext.VmxOnRegion = NULL;
        return STATUS_UNSUCCESSFUL;
    }
    
    g_CpuidContext.VmxEnabled = TRUE;
    return STATUS_SUCCESS;
}

/*
 * Setup VMCS (Virtual Machine Control Structure)
 */
NTSTATUS CpuidSpoof_SetupVmcs(VOID) {
    // Allocate VMCS region
    g_CpuidContext.VmcsRegion = MmAllocateContiguousMemory(
        PAGE_SIZE,
        (PHYSICAL_ADDRESS){0, 0}
    );
    if (!g_CpuidContext.VmcsRegion) {
        return STATUS_INSUFFICIENT_RESOURCES;
    }
    
    g_CpuidContext.VmcsRegionPhys = MmGetPhysicalAddress(g_CpuidContext.VmcsRegion);
    RtlZeroMemory(g_CpuidContext.VmcsRegion, PAGE_SIZE);
    
    // Set VMCS revision
    UINT64 vmxBasic = __readmsr(VMX_BASIC_MSR);
    UINT32 revision = (UINT32)vmxBasic;
    *(UINT32*)g_CpuidContext.VmcsRegion = revision;
    
    // VMCLEAR and VMPTRLD
    VMX_VMCLEAR(&g_CpuidContext.VmcsRegionPhys);
    VMX_VMPTRLD(&g_CpuidContext.VmcsRegionPhys);
    
    // Setup VMCS fields
    // This is a minimal setup - full implementation would set up
    // guest state, host state, execution controls, etc.
    
    // Pin-based controls - enable CPUID exiting
    VMX_VMWRITE(VMCS_CTRL_PIN_BASED, 0);
    
    // Processor-based controls
    // Bit 7 = Use MSR bitmaps
    // Bit 25 = Enable CPUID exiting (CRITICAL)
    VMX_VMWRITE(VMCS_CTRL_PROC_BASED, (1 << 25));
    
    // Secondary processor-based controls
    // Would enable additional features here
    
    return STATUS_SUCCESS;
}

/*
 * CPUID exit handler
 * 
 * This is called when the guest executes CPUID
 * We modify the results before resuming guest execution
 */
VOID CpuidSpoof_HandleCpuidExit(VOID) {
    if (!g_CpuidContext.SpoofingEnabled) {
        // Let the real CPUID execute
        return;
    }
    
    // Read guest RAX (CPUID leaf)
    UINT64 guestRax, guestRbx, guestRcx, guestRdx;
    VMX_VMREAD(VMCS_GUEST_RIP, &guestRax);
    
    // CPUID leaf in RAX
    UINT32 leaf = (UINT32)guestRax;
    UINT32 subLeaf = 0;
    
    // Read RCX for sub-leaf
    // (Would need to access guest register state)
    
    UINT32 eax = 0, ebx = 0, ecx = 0, edx = 0;
    
    switch (leaf) {
        case 0x00000000:  // Vendor ID
        case 0x80000000:  // Extended vendor ID
            // Return fake vendor string
            // "GenuineIntel" -> "AuthenticAMD" or vice versa
            eax = 0x80000004;  // Max extended leaf
            ebx = g_CpuidContext.FakeCpu.VendorEbx;
            edx = g_CpuidContext.FakeCpu.VendorEdx;
            ecx = g_CpuidContext.FakeCpu.VendorEcx;
            break;
            
        case 0x00000001:  // Processor Info and Features
            // Modify family, model, stepping
            eax = (g_CpuidContext.FakeCpu.Family << 8) |
                  (g_CpuidContext.FakeCpu.Model << 4) |
                  g_CpuidContext.FakeCpu.Stepping;
            
            // Modify feature flags
            // Remove VMX bit, add AMD-V bit if spoofing as AMD
            ecx = g_CpuidContext.FakeCpu.FeaturesEcx;
            edx = g_CpuidContext.FakeCpu.FeaturesEdx;
            
            // Hide hypervisor present bit
            ecx &= ~(1 << 31);
            break;
            
        case 0x80000002:  // Brand string part 1
        case 0x80000003:  // Brand string part 2
        case 0x80000004:  // Brand string part 3
            // Return fake CPU name
            {
                INT strOffset = (leaf - 0x80000002) * 16;
                RtlCopyMemory(&eax, &g_CpuidContext.FakeCpu.BrandString[strOffset], 4);
                RtlCopyMemory(&ebx, &g_CpuidContext.FakeCpu.BrandString[strOffset + 4], 4);
                RtlCopyMemory(&ecx, &g_CpuidContext.FakeCpu.BrandString[strOffset + 8], 4);
                RtlCopyMemory(&edx, &g_CpuidContext.FakeCpu.BrandString[strOffset + 12], 4);
            }
            break;
            
        default:
            // For other leaves, execute real CPUID
            // (or could filter/modify as needed)
            int cpuInfo[4];
            __cpuidex(cpuInfo, leaf, subLeaf);
            eax = cpuInfo[0];
            ebx = cpuInfo[1];
            ecx = cpuInfo[2];
            edx = cpuInfo[3];
            break;
    }
    
    // Write modified results to guest registers
    // (Implementation depends on VMCS guest state area access)
    
    // Advance guest RIP past the CPUID instruction
    UINT64 guestRip;
    VMX_VMREAD(VMCS_GUEST_RIP, &guestRip);
    guestRip += 2;  // CPUID is 2 bytes (0F A2)
    VMX_VMWRITE(VMCS_GUEST_RIP, guestRip);
}

/*
 * VM exit handler (main entry point for all VM exits)
 */
VOID CpuidSpoof_VmExitHandler(VOID) {
    UINT64 exitReason;
    VMX_VMREAD(VMCS_CTRL_EXIT_REASON, &exitReason);
    
    exitReason &= 0xFFFF;  // Lower 16 bits contain reason
    
    switch (exitReason) {
        case EXIT_REASON_CPUID:
            CpuidSpoof_HandleCpuidExit();
            break;
            
        case 28:  // MSR read
        case 29:  // MSR write
            // Could also intercept MSR_IA32_PROCESSOR_SERIAL_NUMBER
            break;
            
        default:
            // Handle or inject to guest
            break;
    }
    
    // Resume guest execution
    VMX_VMRESUME();
}

/*
 * Initialize CPUID spoofing
 */
NTSTATUS CpuidSpoof_Initialize(VOID) {
    RtlZeroMemory(&g_CpuidContext, sizeof(g_CpuidContext));
    KeInitializeSpinLock(&g_CpuidContext.Lock);
    
    // Read original CPUID values
    int cpuInfo[4];
    
    // Vendor string
    __cpuid(cpuInfo, 0);
    g_CpuidContext.OriginalCpu.VendorEbx = cpuInfo[1];
    g_CpuidContext.OriginalCpu.VendorEdx = cpuInfo[2];
    g_CpuidContext.OriginalCpu.VendorEcx = cpuInfo[3];
    
    // Processor info
    __cpuid(cpuInfo, 1);
    g_CpuidContext.OriginalCpu.Family = ((cpuInfo[0] >> 8) & 0xF) + 
                                       ((cpuInfo[0] >> 20) & 0xFF);
    g_CpuidContext.OriginalCpu.Model = ((cpuInfo[0] >> 4) & 0xF) |
                                        (((cpuInfo[0] >> 16) & 0xF) << 4);
    g_CpuidContext.OriginalCpu.Stepping = cpuInfo[0] & 0xF;
    g_CpuidContext.OriginalCpu.FeaturesEcx = cpuInfo[2];
    g_CpuidContext.OriginalCpu.FeaturesEdx = cpuInfo[3];
    
    // Brand string
    CHAR brand[48] = {0};
    __cpuid(cpuInfo, 0x80000002);
    RtlCopyMemory(&brand[0], cpuInfo, 16);
    __cpuid(cpuInfo, 0x80000003);
    RtlCopyMemory(&brand[16], cpuInfo, 16);
    __cpuid(cpuInfo, 0x80000004);
    RtlCopyMemory(&brand[32], cpuInfo, 16);
    RtlCopyMemory(g_CpuidContext.OriginalCpu.BrandString, brand, 48);
    
    // Set fake CPU as AMD Ryzen (if original is Intel) or Intel (if original is AMD)
    if (RtlCompareMemory(g_CpuidContext.OriginalCpu.VendorEbx, "Genu", 4) == 4) {
        // Original is Intel, spoof as AMD
        g_CpuidContext.FakeCpu.VendorEbx = 'htuA';  // "Auth"
        g_CpuidContext.FakeCpu.VendorEdx = 'cAMD';  // "DMAc"
        g_CpuidContext.FakeCpu.VendorEcx = 'DMAc';
        g_CpuidContext.FakeCpu.Family = 0x17;  // Zen
        g_CpuidContext.FakeCpu.Model = 0x71;   // Ryzen 7
        RtlCopyMemory(g_CpuidContext.FakeCpu.BrandString,
                     "AMD Ryzen 7 3700X 8-Core Processor         ", 46);
    } else {
        // Original is AMD or other, spoof as Intel
        g_CpuidContext.FakeCpu.VendorEbx = 'uneG';
        g_CpuidContext.FakeCpu.VendorEdx = 'Ieni';
        g_CpuidContext.FakeCpu.VendorEcx = 'letn';
        g_CpuidContext.FakeCpu.Family = 6;
        g_CpuidContext.FakeCpu.Model = 0x9E;  // Coffee Lake
        RtlCopyMemory(g_CpuidContext.FakeCpu.BrandString,
                     "Intel(R) Core(TM) i7-9700K CPU @ 3.60GHz   ", 46);
    }
    
    g_CpuidContext.HaveOriginal = TRUE;
    
    return STATUS_SUCCESS;
}

/*
 * Install CPUID hook via hypervisor
 */
NTSTATUS CpuidSpoof_InstallHook(VOID) {
    NTSTATUS status = CpuidSpoof_Initialize();
    if (!NT_SUCCESS(status)) {
        return status;
    }
    
    status = CpuidSpoof_EnableVmx();
    if (!NT_SUCCESS(status)) {
        return status;
    }
    
    status = CpuidSpoof_SetupVmcs();
    if (!NT_SUCCESS(status)) {
        return status;
    }
    
    // Setup VMM stack
    g_CpuidContext.VmmStack = ExAllocatePoolWithTag(
        NonPagedPool,
        PAGE_SIZE,
        'CPUI'
    );
    if (!g_CpuidContext.VmmStack) {
        return STATUS_INSUFFICIENT_RESOURCES;
    }
    
    // Enable spoofing
    g_CpuidContext.SpoofingEnabled = TRUE;
    
    // VMLAUNCH would happen here to enter VMX non-root mode
    // This requires setting up host state, guest state, etc.
    
    return STATUS_SUCCESS;
}

/*
 * Remove CPUID hook
 */
VOID CpuidSpoof_RemoveHook(VOID) {
    g_CpuidContext.SpoofingEnabled = FALSE;
    
    if (g_CpuidContext.VmxEnabled) {
        VMX_DISABLE();
        g_CpuidContext.VmxEnabled = FALSE;
    }
    
    if (g_CpuidContext.VmcsRegion) {
        MmFreeContiguousMemory(g_CpuidContext.VmcsRegion);
        g_CpuidContext.VmcsRegion = NULL;
    }
    
    if (g_CpuidContext.VmxOnRegion) {
        MmFreeContiguousMemory(g_CpuidContext.VmxOnRegion);
        g_CpuidContext.VmxOnRegion = NULL;
    }
    
    if (g_CpuidContext.VmmStack) {
        ExFreePoolWithTag(g_CpuidContext.VmmStack, 'CPUI');
        g_CpuidContext.VmmStack = NULL;
    }
}

/*
 * Enable/disable spoofing
 */
VOID CpuidSpoof_Enable(BOOLEAN Enable) {
    KIRQL oldIrql;
    KeAcquireSpinLock(&g_CpuidContext.Lock, &oldIrql);
    g_CpuidContext.SpoofingEnabled = Enable;
    KeReleaseSpinLock(&g_CpuidContext.Lock, oldIrql);
}
