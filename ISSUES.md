# ISSUES — Engineering postmortem log

This file is the **structured memory** of major bugs, regressions, and near-misses. Each entry follows the same shape so future fixes stay honest: symptom → root cause → what we tried → lesson (**NEVER AGAIN** where it matters).

**Related:** GitHub issues (e.g. [#6](https://github.com/S8nm/hwid-spoofer/issues/6)), `README.md` (user-facing setup and 24H2 notes).

---

## Absolute rules (do not break)

1. **No auto-enabled unsafe kernel VA probes.** Any path that walks page tables at PML4 level from user-mode–driven vulnerable-driver IOCTLs must stay **opt-in** (e.g. `HWID_ALLOW_UNSAFE_KVA_PTE_SCAN=1` on lab machines only). Shipped defaults must prefer **BSOD avoidance** over “maybe it maps on one reporter’s box.”

2. **No mixing WDM (`ntddk.h`) and IFS (`ntifs.h`) in one driver `.c` translation unit** without a single top-level include strategy. Mixing caused `C2371` `PEPROCESS` / `PETHREAD` redefinition.

3. **No kernel → user named objects without an explicit security descriptor** when user mode must open them (e.g. `OpenEvent`). Default kernel SD → `ACCESS_DENIED` and “revert does nothing.”

4. **No `ExAllocatePool2` without `NTDDI_VERSION >= NTDDI_WIN10_VB` (0x0A000008)** in the driver project; otherwise the API is not declared and you get implicit-int / bogus casts.

5. **No removing safety gates** because “Nal case 0x33 looks fault-tolerant” or one log looked promising. **Induction from one data point is not validation.** PML4-not-present faults are not in the same failure class as PTE/PDE faults for `MmCopyMemory` on 24H2 HVCI/KDP.

6. **No silent “we’ll auto-scan PTE_BASE on 24H2” promises** in docs or UI. Behavior is: image scan + validation first; **unsafe** PML4 index scan **only** when explicitly enabled.

7. **Pre-flight failures are not Stage 4.** Pre-flight uses its own dialog; do not document Pre-flight as surfacing through Stage 4.

---

## Index (resolved themes)

| # | Theme | One-line summary |
|---|--------|------------------|
| 1 | Lazy-filled originals | UI showed placeholders until hooks republished real IDs. |
| 2 | Revert event security | Named event default SD blocked user-mode `OpenEvent`. |
| 3 | Unload / timing | Mapper vs manager teardown ordering caused flaky cleanup. |
| 4 | Driver header mix | `ntddk.h` + `ntifs.h` in one TU → type redefinition build break. |
| 5 | `ExAllocatePool2` + NTDDI | Pool2 APIs gated in WDK headers below Win10 2004 baseline. |
| 6 | **Issue #6 — PML4 scan BSOD (24H2)** | Auto PML4 candidate scan after failed image scan → **BSOD**; reporter’s second log ended at “trying PML4…”. |
| 7 | NalFix | Stale `iqvw64e` services held `\Device\Nal`; purge before load. |
| 8 | Pre-flight | HVCI, non-ASCII temp paths, anti-cheat services → fail fast with clear UI. |

---

## Entry template (copy for new issues)

```markdown
### N — Short title

**Symptom:** What users saw (log line, dialog, BSOD code).

**Root cause:** Technical explanation (one paragraph).

**What we tried:** Bullets — include dead ends (they save time later).

**Resolution:** What shipped (files, flags, version).

**Lesson — NEVER AGAIN:** One imperative sentence.
```

---

## 1 — Lazy-filled originals

**Symptom:** “SPOOFED TO” populated but “Original” stayed placeholders for several seconds.

**Root cause:** Originals are filled from hook observations + disk publish cycles, not instantaneously at spoof RPC time.

**What we tried:** UI timing / refresh cadence adjustments; clarified expectations.

**Resolution:** Documented republish interval (~2–6 s typical).

**Lesson — NEVER AGAIN:** Treat firmware/OS-backed IDs as **eventually consistent** in UX copy unless we block the UI on a definitive capture handshake.

---

## 2 — Revert event security descriptor

**Symptom:** Revert appeared to do nothing; user-mode could not signal the driver.

**Root cause:** Named event created with default kernel security → `OpenEvent` **ACCESS_DENIED**.

**What we tried:** Chasing “driver unload” when the real failure was handle open.

**Resolution:** Explicit **NULL DACL** security descriptor on the revert event (signalling only, not a secret).

**Lesson — NEVER AGAIN:** **Rule 3** — any cross-privilege named object must have an explicit SD and a comment why it is safe.

---

## 3 — Unload / mapper race

**Symptom:** Intermittent crashes or stale device on second run.

**Root cause:** Teardown order between mapper unload and manager assumptions.

**What we tried:** NalFix, ordering fixes, retries.

**Resolution:** Hardened cleanup and stale-service purge (see §7).

**Lesson — NEVER AGAIN:** Assume **every** mapper run leaves SCM cruft until proven otherwise on real machines.

---

## 4 — Driver header mix (`PEPROCESS` / `PETHREAD`)

**Symptom:** `C2371` redefinition when compiling `HelloWorld.c`.

**Root cause:** `ntddk.h` before `hwid_comm.h` pulled in `ntifs.h` → conflicting typedefs.

**What we tried:** Pulling `SECURITY_DESCRIPTOR` via `ntifs` in a header included after `ntddk`.

**Resolution:** **Unify the whole driver TU on `<ntifs.h>`** (single header family).

**Lesson — NEVER AGAIN:** **Rule 2** — one TU, one kernel header family; no “just include ntifs in the helper header.”

---

## 5 — `ExAllocatePool2` and `NTDDI_VERSION`

**Symptom:** `C4013` / `C4312` (implicit `int`, bad casts) on `ExAllocatePool2`.

**Root cause:** WDK declares `ExAllocatePool2` only when `NTDDI_VERSION >= NTDDI_WIN10_VB`; project was on `0x0A000000`.

**What we tried:** Including extra headers (wrong angle).

**Resolution:** **`NTDDI_VERSION=0x0A000008`** in `driver.vcxproj`; trampoline uses **`POOL_FLAG_NON_PAGED_EXECUTE`**.

**Lesson — NEVER AGAIN:** **Rule 4** — when adopting a new kernel API, **check the `#if NTDDI_*` guard** in `wdm.h`, not only the blog post.

---

## 6 — GitHub issue #6: PML4 candidate-index scan BSOD (Win11 24H2 / HVCI / KDP)

**Symptom:** Reporter’s **v4.5.12** `hwid_debug.log` ended exactly at **“trying PML4 candidate-index scan”** — then **BSOD**. First log suggested the scan might be “safe enough” because Nal case `0x33` often survives **PTE/PDE-level** faults.

**Root cause:** **`KM_FindPteBaseForSystem`** walks PML4 indices 256..511 and reads computed PTE addresses via the vulnerable driver. **`MmCopyMemory` / `__try/__except` around lower-level walks does not make PML4-not-present faults “soft”** on all builds: when the **PML4 entry is not present**, the walk fails **above** the level those handlers reasonably cover, and on **24H2 with HVCI/KDP** this surfaces as **`IRQL_NOT_LESS_OR_EQUAL`** / **`KERNEL_SECURITY_CHECK_FAILURE`**-class bugchecks — not a catchable “try next candidate” situation.

**What we tried:** Rationale that “Nal is fault-tolerant” **without** a **local 24H2 + HVCI** repro — that was **wrong** for PML4 scope. Removed or bypassed the gate “to help mappers” → **direct user harm** (BSOD).

**Resolution (v4.5.13+):**

- **`KM_FindPteBaseForSystem` is gated** behind **`HWID_ALLOW_UNSAFE_KVA_PTE_SCAN=1`** only (default **OFF**). Long comment in `manager.c` cites **issue #6** so the gate is not “optimized away” again.
- **Stage 4** dialog and **`SetLastMapFailV`** text state plainly: **iqvw64e mapper cannot proceed** on that configuration; user must **disable HVCI + VBS + hypervisor** and reboot **or** wait for a **different vulnerable driver** (roadmap).
- **`README.md`** 24H2 section matches behavior: **no automatic PML4 scan** in production; link to issue #6 and this file.

**Lesson — NEVER AGAIN:** **Rules 1, 5, 6** — **never** remove or auto-enable unsafe kernel probes from **one reporter log**; **never** equate “fault tolerant at PTE” with “safe at PML4”; **never** ship a change that trades **possible map success** for **certain BSOD risk** on security-hardened SKUs.

---

## 7 — NalFix (stale `iqvw64e` services)

**Symptom:** “Failed to open device” / `\Device\Nal` in use after aborted runs.

**Root cause:** Prior mapper runs left **SCM** entries pointing at `iqvw64e.sys`.

**What we tried:** Manual reboot instructions only.

**Resolution:** **NalFix**: enumerate kernel services, stop+delete any whose image path ends with **`iqvw64e.sys`**, before registering ours.

**Lesson — NEVER AGAIN:** Treat SCM and object namespace as **dirty by default** after any mapper attempt.

---

## 8 — Pre-flight gates

**Symptom:** Cryptic Stage 1–4 failures when the environment was never valid.

**Root cause:** HVCI on, non-ASCII `%TEMP%` paths, anti-cheat kernel drivers already resident.

**What we tried:** Failing deep inside mapping with opaque errors.

**Resolution:** **Pre-flight** checks with **dedicated** “Driver Error - **Pre-flight**” dialog (`README` table).

**Lesson — NEVER AGAIN:** **Rule 7** — fail fast with **which gate** tripped; don’t burn mapper complexity on impossible environments.

---

*Maintainers: when you close a GitHub issue that represents a systemic mistake, add or extend a section here in the same format.*
