# HWID Spoofer

[![Platform](https://img.shields.io/badge/platform-Windows%2010%2F11%20x64-blue)]()
[![Language](https://img.shields.io/badge/language-C-orange)]()
[![Architecture](https://img.shields.io/badge/arch-x64%20only-red)]()
[![License](https://img.shields.io/badge/license-Private-lightgrey)]()

**Single-executable hardware ID spoofer.** Kernel driver, KDMapper, and modern Win32 GUI — all compiled into one `Manager.exe`. No external files, no internet downloads, no Windows reinstallation required.

Randomizes every hardware fingerprint that modern anti-cheat systems read, in under 2 seconds, with zero kernel-mode debug output and full cleanup on exit.

---

## Table of Contents

- [Features](#features)
- [Spoofing Vectors](#spoofing-vectors)
- [Anti-Detection Hardening](#anti-detection-hardening)
- [Architecture](#architecture)
- [Project Structure](#project-structure)
- [Build Requirements](#build-requirements)
- [Build Instructions](#build-instructions)
- [Usage](#usage)
- [Runtime Requirements](#runtime-requirements)
- [ID Logging](#id-logging)
- [How It Works](#how-it-works)
- [Troubleshooting](#troubleshooting)
- [Roadmap](#roadmap)
- [Disclaimer](#disclaimer)

---

## Features

- **All-in-one executable** — driver, mapper, and GUI embedded in a single EXE
- **12+ spoofing vectors** — disk, SMBIOS, MAC, volume, GPU, registry, and more
- **No reboot required** — all changes applied live in kernel memory
- **No test signing** — uses vulnerable driver mapping (DSE bypass)
- **Instant cleanup** — driver files securely wiped within milliseconds of kernel load
- **Modern dark UI** — clean Win32 interface with real-time status
- **Duration selection** — 1 Day, 7 Days, 30 Days, or Until Reboot
- **Original ID backup** — captures all original values before spoofing
- **One-click revert** — restore all original hardware IDs instantly
- **Detailed logging** — human-readable log saved to Documents folder

---

## Spoofing Vectors

Every hardware identifier that major anti-cheat systems query is intercepted and randomized:

| # | Vector | Kernel Method | What It Defeats |
|---|--------|---------------|-----------------|
| 1 | **Disk Serial Number** | `IOCTL_STORAGE_QUERY_PROPERTY` dispatch hook | WMI `Win32_DiskDrive`, most AC serial checks |
| 2 | **SMART Drive Data** | `IOCTL_SMART_RCV_DRIVE_DATA` dispatch hook | Advanced ACs reading raw SMART identity |
| 3 | **ATA IDENTIFY** | `IOCTL_ATA_PASS_THROUGH` dispatch hook | ACs sending raw ATA commands |
| 4 | **NVMe IDENTIFY** | `IOCTL_STORAGE_PROTOCOL_COMMAND` dispatch hook | NVMe drive identity queries |
| 5 | **Disk Model / Firmware** | Patched inside storage descriptors + ATA response | Device fingerprinting |
| 6 | **SMBIOS Tables** | Physical memory patch — Types 0, 1, 2, 3 strings + UUID | EAC, BattlEye, Vanguard, Ricochet |
| 7 | **NIC MAC Address** | NDIS miniport dispatch hook (OID intercept) | All ACs, network fingerprinting |
| 8 | **NTFS Volume Serial** | `IRP_MJ_QUERY_VOLUME_INFORMATION` filesystem hook | Many ACs, Windows telemetry |
| 9 | **BIOS Registry Keys** | `ZwSetValueKey` on `HKLM\HARDWARE\...\BIOS` | Common registry-based AC checks |
| 10 | **GPU Adapter ID** | Registry `HardwareInformation.AdapterString` spoof | GPU-based fingerprinting |
| 11 | **System UUID** | SMBIOS Type 1 UUID field (16-byte binary patch) | EAC, BattlEye system identity |
| 12 | **Motherboard Serial** | SMBIOS Type 2 serial string patch | Motherboard-based HWID bans |

All vectors are spoofed atomically in a single `DriverEntry` call — no multi-step process, no partial states.

---

## Anti-Detection Hardening

The driver and manager are built with multiple layers of stealth to minimize detection surface:

### Kernel Driver

| Technique | Description |
|-----------|-------------|
| **Zero debug output** | No `DbgPrint`, `KdPrint`, or `DbgPrintEx` calls anywhere in the binary |
| **MDL-based memory writes** | Uses `IoAllocateMdl` + `MmMapLockedPagesSpecifyCache` instead of toggling CR0 WP bit (which ACs detect) |
| **Spinlock-protected hooks** | All inline hooks guarded by `KSPIN_LOCK` — thread-safe under concurrent IOCTL storms, no BSOD |
| **No DriverUnload** | Mapped drivers should never expose an unload routine — prevents AC enumeration |
| **14-byte inline hooks** | Absolute `MOV RAX + JMP RAX` patching with saved original bytes for clean call-through |
| **Obfuscated identifiers** | Short variable names, no debug strings, no function name exports |
| **XOR-encoded driver names** | Target driver names decoded at runtime, not stored as plaintext |

### Manager (User-Mode)

| Technique | Description |
|-----------|-------------|
| **Randomized temp paths** | Drivers extracted to `%TEMP%\Microsoft\<random_hex>\<random>.tmp` |
| **Randomized service names** | Vulnerable driver registered under a different 8-char hex name every run |
| **Immediate secure wipe** | Both `.sys` files overwritten with zeros and deleted within milliseconds of kernel load |
| **Hidden + system attributes** | Temp directory and files marked `FILE_ATTRIBUTE_HIDDEN | FILE_ATTRIBUTE_SYSTEM` |
| **Embedded resources** | Both drivers compiled into the EXE as RC resources — nothing downloaded at runtime |
| **No leftover artifacts** | Temp directory removed after wipe; service entry deleted on unload |

---

## Architecture

```
┌──────────────────────────────────────────────────────┐
│                    Manager.exe                        │
│  ┌────────────┐  ┌────────────┐  ┌────────────────┐  │
│  │  Win32 GUI  │  │  KDMapper  │  │   Embedded     │  │
│  │  (Dark UI)  │  │  (Intel)   │  │   Resources    │  │
│  │             │  │            │  │                │  │
│  │ • Status    │  │ • Extract  │  │ • iqvw64e.sys  │  │
│  │ • Controls  │  │ • Load     │  │   (34KB Intel) │  │
│  │ • ID View   │  │ • Map      │  │ • Spoofer.sys  │  │
│  │ • Logging   │  │ • Execute  │  │   (20KB driver)│  │
│  │ • Revert    │  │ • Cleanup  │  │                │  │
│  └──────┬─────┘  └──────┬─────┘  └────────────────┘  │
│         │               │                             │
└─────────┼───────────────┼─────────────────────────────┘
          │               │
          │    ┌──────────▼──────────┐
          │    │   iqvw64e.sys       │
          │    │   (Intel signed)    │
          │    │   Maps physical mem │
          │    └──────────┬──────────┘
          │               │  IOCTL 0x80862007
          │    ┌──────────▼──────────┐
          │    │   Kernel Memory     │
          │    │   • Copy PE sections│
          │    │   • Fix relocations │
          │    │   • Resolve imports │
          │    │   • Call DriverEntry │
          │    └──────────┬──────────┘
          │               │
          │    ┌──────────▼──────────┐
          └───►│   Spoofer Driver    │
               │   (HelloWorld.sys)  │
               │                     │
               │ • Hook disk dispatch│
               │ • Patch SMBIOS      │
               │ • Hook NDIS         │
               │ • Hook filesystem   │
               │ • Spoof registry    │
               │ • Write log file    │
               └─────────────────────┘
```

---

## Project Structure

```
hwid Spoofer/
├── HWIDSpoofer.sln              # Visual Studio solution
├── README.md
│
├── driver/
│   ├── HelloWorld.c             # Kernel driver source (~600 lines)
│   │                            #   - Inline hook engine (MDL-based)
│   │                            #   - 12 spoofing vector handlers
│   │                            #   - Random ID generation (LCG PRNG)
│   │                            #   - Binary log writer
│   │                            #   - SMBIOS physical memory patcher
│   └── driver.vcxproj           # MSVC kernel-mode build config
│
├── manager/
│   ├── manager.c                # GUI + integrated KDMapper (~1400 lines)
│   │                            #   - Win32 dark-themed UI
│   │                            #   - Resource extraction & secure wipe
│   │                            #   - Full PE mapper (relocs + imports)
│   │                            #   - Shellcode-based DriverEntry caller
│   │                            #   - Log reader & display
│   ├── manager.vcxproj          # MSVC user-mode build config
│   ├── manager.rc               # Resource script (embeds .sys files)
│   ├── resource.h               # Resource IDs
│   └── drivers/                 # Pre-built binaries (embedded at compile)
│       ├── iqvw64e.sys          # Intel Network Adapter Diagnostic Driver (signed)
│       └── HelloWorld.sys       # Compiled spoofer kernel driver
│
└── mapper/
    └── kdmapper.c               # Standalone mapper (reference/testing)
```

---

## Build Requirements

| Requirement | Version | Notes |
|-------------|---------|-------|
| **Visual Studio** | 2022+ | C++ Desktop Development workload |
| **Windows SDK** | 10.0.26100.0+ | Included with VS installer |
| **Windows Driver Kit** | Matching SDK | Provides km headers and libs |
| **Platform** | x64 only | No x86 or ARM support |
| **MSBuild** | 17.0+ | Ships with Visual Studio |

---

## Build Instructions

### Quick Build (Command Line)

```batch
:: Step 1: Build the kernel driver
msbuild driver\driver.vcxproj /p:Configuration=Release /p:Platform=x64

:: Step 2: Copy compiled driver to manager resources
copy driver\build\Release\HelloWorld\HelloWorld.sys manager\drivers\

:: Step 3: Ensure iqvw64e.sys is in manager\drivers\ (obtain separately)

:: Step 4: Build the manager (embeds both .sys files)
msbuild manager\manager.vcxproj /p:Configuration=Release /p:Platform=x64
```

### Output

```
manager\build\Release\Manager\Manager.exe    (~220KB, self-contained)
```

This single file is everything you need. No DLLs, no config files, no runtime dependencies.

### Visual Studio Build

1. Open `HWIDSpoofer.sln`
2. Set configuration to **Release | x64**
3. Build `driver` project first
4. Copy output `HelloWorld.sys` to `manager\drivers\`
5. Build `manager` project
6. Output EXE is in `manager\build\Release\Manager\`

---

## Usage

### First Run

1. **Disable Memory Integrity** — Windows Security → Device Security → Core Isolation → Memory Integrity → **Off** → Reboot
2. Run `Manager.exe` as **Administrator** (right-click → Run as administrator)

### Spoofing

1. Select spoof duration from the dropdown:
   - **1 Day** — IDs revert after 24 hours
   - **7 Days** — IDs revert after 1 week
   - **30 Days** — IDs revert after 1 month
   - **Until Reboot** — IDs revert on next restart
2. Click **Change HWID** — all 12 vectors spoofed in ~2 seconds
3. Click **Refresh HWIDs** to verify all IDs changed in the UI
4. Launch your game — anti-cheat sees spoofed hardware

### Reverting

1. Click **Revert to Original** — restores all saved original IDs
2. Or simply **reboot** — mapped driver is non-persistent

### Cleanup

Closing `Manager.exe` triggers automatic cleanup:
- Vulnerable driver service stopped and deleted
- All temp files already wiped (done during load)
- No registry leftovers, no files on disk

---

## Runtime Requirements

| Requirement | Details |
|-------------|---------|
| **OS** | Windows 10 or 11, 64-bit |
| **Privileges** | Administrator (UAC elevation required) |
| **Memory Integrity** | Must be **disabled** (HVCI blocks vulnerable driver loading) |
| **Secure Boot** | Can remain **enabled** (DSE bypass is via signed driver, not boot modification) |
| **Antivirus** | May need exclusion for `Manager.exe` (some AVs flag KDMapper behavior) |
| **Disk** | ~1MB free in `%TEMP%` (briefly, during driver extraction) |

---

## ID Logging

### Binary Log (Driver → Manager)

The kernel driver writes a packed binary struct to:

```
C:\ProgramData\hwid_log.bin    (hidden + system attributes)
```

This file contains original and spoofed values for every vector. The manager reads it on "Refresh" and **deletes it immediately** after parsing.

### Human-Readable Log

After reading the binary log, the manager saves a formatted text log to:

```
%USERPROFILE%\Documents\HWID_Spoof_Log.txt
```

Example output:

```
=== HWID Spoof Log ===
Generated: 2026-04-03 20:15:32

[Disk Serial]
  Original: WD-WMC4N0E1234
  Spoofed:  WD-WMAZA7F3A2B1C

[Model Number]
  Original: WDC WD10EZEX-08WN4A0
  Spoofed:  WDC WD10EZEX-4D2E8F1A

[BIOS Serial]
  Original: H1RG9T2
  Spoofed:  BIOS-8A3F21D7E9B4C

[Motherboard Serial]
  Original: /7XRPF32/CN129
  Spoofed:  BS-F71A3C9D82E5B

[System UUID]
  Original: 4C4C4544-0048-3110-8052-B8C04F395032
  Spoofed:  7A3F21D8-E9B4-C156-2D8F-A73E1B940C5D

[MAC Address]
  Original: D8:BB:C1:23:45:67
  Spoofed:  02:7A:3F:21:D8:E9

[Volume Serial]
  Original: 0xAE231F4B
  Spoofed:  0xD82F1A73

[GPU ID]
  Original: NVIDIA GeForce RTX 3080
  Spoofed:  GPU-7A3F21D8E9B4C
```

---

## How It Works

### Phase 1: Extraction (~50ms)

1. Manager creates a randomized temp directory under `%TEMP%\Microsoft\`
2. Both embedded `.sys` files extracted with hidden + system attributes
3. Random filenames assigned (e.g., `a7f3c2d1.tmp`)

### Phase 2: Vulnerable Driver Load (~200ms)

1. `iqvw64e.sys` (Intel) registered as a kernel service with a random 8-char name
2. Service started — driver creates `\\Device\\Nal` device
3. **File immediately wiped** (overwritten with zeros, then deleted)
4. Device handle opened via `\\.\Nal` for physical memory IOCTL

### Phase 3: Driver Mapping (~500ms)

1. Kernel base address located via `NtQuerySystemInformation`
2. Spoofer PE file parsed — sections, relocations, imports
3. PE sections written to kernel memory via `iqvw64e.sys` IOCTL (`0x80862007`, case `0x19` MapIoSpace)
4. Relocations applied (delta-based `IMAGE_REL_BASED_DIR64`)
5. Imports resolved against `ntoskrnl.exe` exports
6. Shellcode stub written — calls `DriverEntry(NULL, NULL)`
7. **Spoofer file immediately wiped** from disk

### Phase 4: Spoofing (~100ms)

`DriverEntry` executes in kernel context:

1. **Generate IDs** — LCG PRNG seeded from `KeQueryPerformanceCounter`, generates all fake serials/MACs/UUIDs
2. **Hook disk driver** — `\\Driver\\Disk` `IRP_MJ_DEVICE_CONTROL` patched with 14-byte inline hook
3. **Hook NDIS** — `\\Driver\\ndis` `IRP_MJ_DEVICE_CONTROL` hooked for MAC address OIDs
4. **Hook filesystem** — `\\FileSystem\\Ntfs` `IRP_MJ_QUERY_VOLUME_INFORMATION` hooked for volume serial
5. **Patch SMBIOS** — Physical memory scanned for `_SM_` anchor, Types 0/1/2/3 strings and UUID patched in-place
6. **Spoof registry** — BIOS keys and GPU adapter string overwritten via `ZwSetValueKey`
7. **Write log** — Binary struct written to `C:\ProgramData\hwid_log.bin`

### Phase 5: Cleanup (on exit)

1. Vulnerable driver service stopped and deleted from SCM
2. Temp directory removed (files already wiped in Phase 2-3)
3. No persistent kernel objects remain (mapped driver has no unload routine)

---

## Troubleshooting

| Problem | Cause | Solution |
|---------|-------|----------|
| **"Failed to start service" (error 1275)** | Memory Integrity / HVCI is enabled | Disable in Windows Security → Core Isolation |
| **"Driver signature verification failed" (error 577)** | Uncommon — DSE blocking Intel driver | Verify `iqvw64e.sys` is the correct signed binary |
| **"Failed to extract embedded driver files"** | AV quarantined the EXE or blocked extraction | Add exclusion for `Manager.exe` and `%TEMP%` |
| **"Failed to open device"** | `iqvw64e.sys` loaded but device not created | Another instance may be running; reboot and retry |
| **BSOD during spoofing** | Hook collision with AV kernel driver | Disable real-time AV protection before running |
| **IDs not changing after spoof** | WMI cache or application cache | Close and reopen the application reading HWIDs |
| **Log file empty or missing** | Driver couldn't write to `C:\ProgramData` | Run as admin; check folder permissions |
| **Some IDs revert immediately** | Application re-reads from firmware, not OS cache | Expected for firmware-level queries (planned fix) |

---

## Roadmap

### Vulnerable Driver Improvements

The current mapper uses `iqvw64e.sys` (Intel Network Adapter Diagnostic Driver, IOCTL `0x80862007`). Future versions will support hot-swappable vulnerable drivers via a config struct:

| Driver | Vendor | IOCTL | Notes |
|--------|--------|-------|-------|
| `iqvw64e.sys` | Intel | `0x80862007` | **Current default** — widely available, well-tested |
| `RTCore64.sys` | MSI (Afterburner) | `0x80002048` | Commonly available, different blocklist status |
| `gdrv.sys` | Gigabyte | `0xC3502004` | Ships with Gigabyte utilities |
| `AsIO3.sys` | ASUS | `0xA0406D44` | Ships with ASUS motherboard software |
| `ene.sys` | ENE Technology | `0x80102040` | Less commonly blocklisted |
| `dbutil_2_3.sys` | Dell | `0x9B0C1EC8` | Dell BIOS utility driver |

### Planned Features

- **Driver-agnostic mapper** — single config struct to swap vulnerable drivers
- **EFI bootkit loader** — bypass DSE without any vulnerable driver dependency
- **TPM PCR spoofing** — Windows 11 attestation bypass
- **Disk firmware-level serial** — persistent serial change that survives driver unload
- **Network adapter firmware MAC** — persistent MAC that survives reboot
- **CPUID spoofing** — intercept processor identification instructions
- **Monitor EDID spoofing** — display hardware fingerprint randomization
- **Hypervisor-based hooking** — VT-x EPT hooks instead of inline patches

---

## Disclaimer

This software is provided for **educational and research purposes only**. The authors are not responsible for any misuse. Using this tool to circumvent anti-cheat systems may violate the terms of service of games and platforms. Use at your own risk.

---

*Built with C, WDK, and Win32 API. No frameworks, no dependencies, no bloat.*
