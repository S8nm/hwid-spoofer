/*
 * spoof_call.h - Return address spoofing for kernel API calls.
 *
 * When a manually-mapped driver calls kernel functions, the return address
 * on the stack points into unregistered memory. Anti-cheat stack walkers
 * flag this immediately.
 *
 * Solution: find an `add rsp, 0x28; ret` gadget inside ntoskrnl.exe and
 * build a shellcode stub that:
 *   1. Saves real return address into a scratch register
 *   2. Pushes the gadget address as the fake return address
 *   3. Jumps to the target function
 *   4. The target returns to the gadget, which does `add rsp, 0x28; ret`
 *      back to our real caller via the shellcode's fixup
 *
 * Pattern adapted from External_Rust_AI driver_prompt.md.
 */

#ifndef HWID_SPOOF_CALL_H
#define HWID_SPOOF_CALL_H

#include <ntifs.h>
#include <ntimage.h>
/* ----------------------------------------------------------------
 * Globals
 * ---------------------------------------------------------------- */

static PVOID g_SpoofGadget     = NULL;   /* addr of `add rsp, 0x28; ret` */
static PVOID g_SpoofStub       = NULL;   /* allocated shellcode stub */
static BOOLEAN g_SpoofCallReady = FALSE;

/* ----------------------------------------------------------------
 * Gadget scanner
 * ---------------------------------------------------------------- */

/* Searches ntoskrnl .text section for the byte sequence:
 *   48 83 C4 28 C3   =>  add rsp, 0x28 ; ret
 */
static PVOID SpoofCall_FindGadget(PVOID kernelBase) {
    if (!kernelBase) return NULL;
    PIMAGE_DOS_HEADER dos = (PIMAGE_DOS_HEADER)kernelBase;
    if (dos->e_magic != IMAGE_DOS_SIGNATURE) return NULL;
    PIMAGE_NT_HEADERS64 nt = (PIMAGE_NT_HEADERS64)(
        (PUCHAR)kernelBase + dos->e_lfanew);
    if (nt->Signature != IMAGE_NT_SIGNATURE) return NULL;
    PIMAGE_SECTION_HEADER sec = IMAGE_FIRST_SECTION(nt);

    for (USHORT i = 0; i < nt->FileHeader.NumberOfSections; i++) {
        if (sec[i].Name[0] == '.' && sec[i].Name[1] == 't' &&
            sec[i].Name[2] == 'e' && sec[i].Name[3] == 'x' &&
            sec[i].Name[4] == 't')
        {
            PUCHAR start = (PUCHAR)kernelBase + sec[i].VirtualAddress;
            SIZE_T size = sec[i].Misc.VirtualSize;

            for (SIZE_T j = 0; j + 4 < size; j++) {
                if (start[j]     == 0x48 &&
                    start[j + 1] == 0x83 &&
                    start[j + 2] == 0xC4 &&
                    start[j + 3] == 0x28 &&
                    start[j + 4] == 0xC3)
                {
                    return &start[j];
                }
            }
        }
    }
    return NULL;
}

/* ----------------------------------------------------------------
 * Shellcode stub
 * ----------------------------------------------------------------
 *
 * The stub is called instead of the real target. It:
 *   - Pops the real return address into r11
 *   - Pushes space for shadow + our real return addr
 *   - Pushes the gadget address (so the callee returns to gadget)
 *   - Jumps to the target function pointer stored after shellcode
 *
 * Layout of allocated block:
 *   [0x00 .. shellcode_size-1]  : shellcode bytes
 *   [shellcode_size .. +7]      : target function pointer (PVOID)
 *   [shellcode_size+8 .. +15]   : gadget address (PVOID)
 *
 * x64 shellcode (using r11 as scratch, r11 is volatile in MS ABI):
 *
 *   pop  r11                    ; save real return address
 *   sub  rsp, 0x28              ; allocate shadow space
 *   mov  [rsp+0x20], r11        ; store real ret addr below shadow
 *   lea  rax, [rip+XX]          ; load gadget addr ptr
 *   mov  rax, [rax]             ; dereference -> gadget addr
 *   push rax                    ; push gadget as fake return addr
 *   lea  rax, [rip+YY]          ; load target fn ptr
 *   mov  rax, [rax]             ; dereference -> target
 *   jmp  rax                    ; tail-call to target
 *
 * The target sees gadget as return addr. Gadget does:
 *   add rsp, 0x28; ret
 * which pops our real return addr (stored at [rsp+0x28] before push).
 *
 * Stack math: pop(+8) - sub 0x30(-0x30) + push(-8) = -0x30 from entry.
 * Real return at [entry_rsp - 0x30 + push + 0x30] = [jmp_rsp + 0x30].
 * Target ret(+8) + gadget add(+0x28) = +0x30 from jmp_rsp => correct.
 */

/*
 * Pre-assembled shellcode. The RIP-relative offsets for the two LEA
 * instructions are filled in at init time.
 */
static const UCHAR g_SpoofShellcode[] = {
    /* 00 */ 0x41, 0x5B,                         /* pop  r11                    */
    /* 02 */ 0x48, 0x83, 0xEC, 0x30,             /* sub  rsp, 0x30             */
    /* 06 */ 0x4C, 0x89, 0x5C, 0x24, 0x28,       /* mov  [rsp+0x28], r11       */
    /* 0B */ 0x48, 0x8D, 0x05, 0x00, 0x00, 0x00, 0x00,  /* lea rax, [rip+??] -> gadget_ptr */
    /* 12 */ 0x48, 0x8B, 0x00,                    /* mov  rax, [rax]            */
    /* 15 */ 0x50,                                /* push rax (fake return)     */
    /* 16 */ 0x48, 0x8D, 0x05, 0x00, 0x00, 0x00, 0x00,  /* lea rax, [rip+??] -> target_ptr */
    /* 1D */ 0x48, 0x8B, 0x00,                    /* mov  rax, [rax]            */
    /* 20 */ 0xFF, 0xE0,                          /* jmp  rax                   */
};

#define SPOOF_SC_SIZE     sizeof(g_SpoofShellcode)  /* 0x22 = 34 bytes */
#define SPOOF_BLOCK_SIZE  (SPOOF_SC_SIZE + 16)      /* +8 target_ptr +8 gadget_ptr */

/* Offsets within the allocated block for the data pointers */
#define SPOOF_OFF_TARGET  SPOOF_SC_SIZE
#define SPOOF_OFF_GADGET  (SPOOF_SC_SIZE + 8)

/* ----------------------------------------------------------------
 * Init & API
 * ---------------------------------------------------------------- */

/*
 * SpoofCall_Init - Call once from DriverEntry.
 * Requires kernelBase from Cleaner_GetKernelInfo or equivalent.
 */
static BOOLEAN SpoofCall_Init(PVOID kernelBase) {
    if (!kernelBase) return FALSE;

    g_SpoofGadget = SpoofCall_FindGadget(kernelBase);
    if (!g_SpoofGadget) return FALSE;

    g_SpoofStub = ExAllocatePool2(
        POOL_FLAG_NON_PAGED_EXECUTE, SPOOF_BLOCK_SIZE, 'fpSC');
    if (!g_SpoofStub) return FALSE;

    /* Copy shellcode template */
    RtlCopyMemory(g_SpoofStub, g_SpoofShellcode, SPOOF_SC_SIZE);

    /* Store gadget address in the data area */
    *(PVOID*)((PUCHAR)g_SpoofStub + SPOOF_OFF_GADGET) = g_SpoofGadget;
    /* Target pointer slot is zeroed; will be set per-call */
    *(PVOID*)((PUCHAR)g_SpoofStub + SPOOF_OFF_TARGET) = NULL;

    /*
     * Patch RIP-relative LEA for gadget_ptr:
     *   LEA at offset 0x0B, operand at 0x0E, instruction ends at 0x12
     *   target address = stub + SPOOF_OFF_GADGET
     *   RIP at instruction end = stub + 0x12
     *   disp32 = (stub + SPOOF_OFF_GADGET) - (stub + 0x12)
     */
    INT32 gadgetDisp = (INT32)(SPOOF_OFF_GADGET - 0x12);
    *(INT32*)((PUCHAR)g_SpoofStub + 0x0E) = gadgetDisp;

    /*
     * Patch RIP-relative LEA for target_ptr:
     *   LEA at offset 0x16, operand at 0x19, instruction ends at 0x1D
     *   target address = stub + SPOOF_OFF_TARGET
     *   RIP at instruction end = stub + 0x1D
     *   disp32 = (stub + SPOOF_OFF_TARGET) - (stub + 0x1D)
     */
    INT32 targetDisp = (INT32)(SPOOF_OFF_TARGET - 0x1D);
    *(INT32*)((PUCHAR)g_SpoofStub + 0x19) = targetDisp;

    g_SpoofCallReady = TRUE;
    return TRUE;
}

/*
 * SpoofCall_SetTarget - Set the function to be called via the spoof stub.
 * Must be called before invoking the stub. NOT thread-safe; serialize usage
 * or use per-CPU stubs for concurrent calls.
 */
static __forceinline VOID SpoofCall_SetTarget(PVOID target) {
    *(PVOID*)((PUCHAR)g_SpoofStub + SPOOF_OFF_TARGET) = target;
}

/*
 * Typed call macros.
 * Usage:
 *   NTSTATUS st = SPOOF_CALL(NTSTATUS, ObReferenceObjectByName,
 *                            &uName, OBJ_CASE_INSENSITIVE, ...);
 *
 * WARNING: These macros are NOT thread-safe because they share one target
 * slot. For the HWID spoofer this is fine since calls happen sequentially
 * during DriverEntry. For concurrent use, allocate per-CPU stubs.
 */

/*
 * C-compatible call macros. Parameter types must be provided explicitly.
 *
 * Usage examples:
 *   SPOOF_CALL0(NTSTATUS, MyFunc);
 *   SPOOF_CALL4(NTSTATUS, ZwQuerySystemInformation,
 *               ULONG,cls, PVOID,info, ULONG,len, PULONG,ret);
 *
 * The 'sig' parameters are: type1,arg1, type2,arg2, ...
 */

/* 0-arg */
#define SPOOF_CALL0(ret, fn)                                    \
    (SpoofCall_SetTarget((PVOID)(fn)),                          \
     ((ret(NTAPI*)(void))g_SpoofStub)())

/* 1-arg: ret, fn, T1, a1 */
#define SPOOF_CALL1(ret, fn, T1, a1)                            \
    (SpoofCall_SetTarget((PVOID)(fn)),                          \
     ((ret(NTAPI*)(T1))g_SpoofStub)(a1))

/* 2-arg: ret, fn, T1,a1, T2,a2 */
#define SPOOF_CALL2(ret, fn, T1,a1, T2,a2)                     \
    (SpoofCall_SetTarget((PVOID)(fn)),                          \
     ((ret(NTAPI*)(T1,T2))g_SpoofStub)(a1,a2))

/* 3-arg */
#define SPOOF_CALL3(ret, fn, T1,a1, T2,a2, T3,a3)              \
    (SpoofCall_SetTarget((PVOID)(fn)),                          \
     ((ret(NTAPI*)(T1,T2,T3))g_SpoofStub)(a1,a2,a3))

/* 4-arg (most common for NT APIs) */
#define SPOOF_CALL4(ret, fn, T1,a1, T2,a2, T3,a3, T4,a4)      \
    (SpoofCall_SetTarget((PVOID)(fn)),                          \
     ((ret(NTAPI*)(T1,T2,T3,T4))g_SpoofStub)(a1,a2,a3,a4))

/* 7-arg (e.g. ObReferenceObjectByName) */
#define SPOOF_CALL7(ret, fn, T1,a1, T2,a2, T3,a3, T4,a4,      \
                    T5,a5, T6,a6, T7,a7)                        \
    (SpoofCall_SetTarget((PVOID)(fn)),                          \
     ((ret(NTAPI*)(T1,T2,T3,T4,T5,T6,T7))                     \
      g_SpoofStub)(a1,a2,a3,a4,a5,a6,a7))

#endif /* HWID_SPOOF_CALL_H */
