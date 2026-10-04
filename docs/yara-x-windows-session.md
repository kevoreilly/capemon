# YARA-X migration — Windows session handoff

Paste this whole file into the new session so it has full context.

## Where we are

capemon's in-monitor YARA scanning is fully isolated behind `CAPE/YaraHarness.h`
(7 functions + `NameByAddress`). On the previous (macOS) session we added a
second backend implementing that same interface against **YARA-X** instead of
libyara, selected by the `CAPE_USE_YARA_X` preprocessor define. libyara is
untouched and remains the default.

Already committed to the working tree (all additive):

| Path | State |
|---|---|
| `CAPE/YaraHarnessX.c` | **new** — complete YARA-X backend (~640 LoC). Written against the real v1.20.0 header, **never compiled**. |
| `CAPE/YaraHarness.h` | `#include "yara.h"` skipped when `CAPE_USE_YARA_X` is defined |
| `yara-x/include/yara_x.h` | vendored YARA-X C API header, **v1.20.0** |
| `yara-x/lib/` | **empty** — Step 1 fills it |
| `docs/yara-x-migration.md` | design notes / rationale |
| `docs/yara-x-windows-session.md` | this file |
| `capemon.vcxproj` / `.filters` | **`Release\|x64` block already wired** for the YARA-X backend (Step 2 below is pre-done for that one config); the other 3 configs still use libyara |

Goal of the Windows session: do Step 1 (build the libs) and Step 3 (build + test)
to get **x64 Release** capemon building and passing the regression checklist with
the YARA-X backend. Step 2 is only "verify / adjust the linker deps". Then repeat
Step 2 + 3 for Win32 Release.

---

## Decisions already made (don't re-litigate, just apply)

* **`pulley` Cargo feature ON.** YARA-X compiles rule conditions to WASM and runs
  them in wasmtime. Default backend is Cranelift JIT, which allocates
  **RWX/executable memory** at scan time — bad inside an injected monitoring DLL
  (trips RWX detection, blocked by ACG/CFG). `pulley` switches wasmtime to a
  portable bytecode interpreter: no JIT, no RWX. Slightly slower condition eval,
  irrelevant for CAPE's simple `any of them` rules.
* **Static CRT (`-C target-feature=+crt-static`)** to match capemon's `/MT`.
  This produces `libcmt`, which conflicts with capemon **Debug** (`/MTd`,
  `libcmtd`). So: **Release configs only** for now. Debug keeps libyara.
* Compiled-rule cache filename is `capemon.yrx` (not `.yac`) — different,
  version-locked format. Handled in code.
* One `YRX_SCANNER` per thread (YARA-X scanners aren't thread-safe; the
  `YRX_RULES` object is shared). Handled in code.
* `magic` module deliberately excluded (would need libmagic). `pe`, `dotnet`,
  `hash`, `math`, `string`, `console`, `elf`, `macho`, `lnk` are in the default
  feature set and are enough.

---

## Step 1 — build the YARA-X static libraries

`yara-x-capi` has `crate-type = ["staticlib", ...]`, so **plain `cargo build`
produces the `.lib`** — no `cargo-c` needed (the C header is already vendored).

Prereqs: `rustup` with MSVC toolchain, and the "Desktop development with C++"
VS workload. From a **x64 Native Tools Command Prompt**:

```bat
rustup target add x86_64-pc-windows-msvc i686-pc-windows-msvc

git clone --depth 1 --branch v1.20.0 https://github.com/VirusTotal/yara-x C:\src\yara-x
cd C:\src\yara-x

set RUSTFLAGS=-C target-feature=+crt-static

:: ---- x64 ----
cargo build -p yara-x-capi --release --features pulley --target x86_64-pc-windows-msvc

:: ---- x86 ----
cargo build -p yara-x-capi --release --features pulley --target i686-pc-windows-msvc
```

Artefacts:

```
C:\src\yara-x\target\x86_64-pc-windows-msvc\release\yara_x_capi.lib
C:\src\yara-x\target\i686-pc-windows-msvc\release\yara_x_capi.lib
```

Get the exact list of **system libs** the static lib needs (Rust std + wasmtime
pull in a handful):

```bat
cargo rustc -p yara-x-capi --release --features pulley ^
  --target x86_64-pc-windows-msvc --crate-type staticlib -- ^
  --print native-static-libs
```

It prints a line like
`native-static-libs: kernel32.lib advapi32.lib ntdll.lib userenv.lib ws2_32.lib bcrypt.lib ...`
— **copy that list**, you need it in Step 2.

Vendor into the repo (rename per-arch like the libyara libs):

```bat
copy C:\src\yara-x\target\x86_64-pc-windows-msvc\release\yara_x_capi.lib  <repo>\yara-x\lib\yara_x64.lib
copy C:\src\yara-x\target\i686-pc-windows-msvc\release\yara_x_capi.lib    <repo>\yara-x\lib\yara_x32.lib
```

Sanity-check the header matches: `yara-x\include\yara_x.h` should already say
`v1.20.0`-era content (it's `capi/include/yara_x.h` from the same tag). If you
built a different tag, replace it with that tag's `capi/include/yara_x.h`.

> Note: the capemon DLL will grow by roughly **4–8 MB** (Rust std + wasmtime).
> Measure `capemon_x64.dll` before/after.

---

## Step 2 — wire `capemon.vcxproj`

**Already done for `Release|x64`** (commit in the tree). Just verify:
`git diff capemon.vcxproj` should show, in the `Release|x64` block only,
`CAPE_USE_YARA_X` added, `libyara\include`→`yara-x\include`,
`libyara\lib`→`yara-x\lib`, `libyara64.lib`→`yara_x64.lib;ntdll.lib;userenv.lib;bcrypt.lib;advapi32.lib`,
and `YaraHarness.c` / `YaraHarnessX.c` swapped via `ExcludedFromBuild` conditions.
After Step 1's `native-static-libs` output, adjust the extra `*.lib` names in
`<AdditionalDependencies>` if they differ.

For **Win32 Release** (do this after x64 is green), repeat the same edits in the
`Release|Win32` block (around line 145).

In that block:

1. `<PreprocessorDefinitions>` — prepend `CAPE_USE_YARA_X;`
   (currently starts `WIN32;_WIN64;_CRT_SECURE_NO_WARNINGS;...`).

2. `<AdditionalIncludeDirectories>` — change `.\libyara\include` → `.\yara-x\include`.

3. `<AdditionalLibraryDirectories>` — change `$(ProjectDir)\libyara\lib` →
   `$(ProjectDir)\yara-x\lib`.

4. `<AdditionalDependencies>` — replace `libyara64.lib;` with
   `yara_x64.lib;` **plus the system libs from Step 1** that aren't already
   there. Existing line is:
   `libyara64.lib;bson.lib;crypt32.lib;ws2_32.lib;%(AdditionalDependencies)`
   → e.g.:
   `yara_x64.lib;ntdll.lib;userenv.lib;bcrypt.lib;advapi32.lib;bson.lib;crypt32.lib;ws2_32.lib;%(AdditionalDependencies)`
   (`crypt32.lib` was libyara's — harmless to leave.)

Then swap the source file for this config. Find:
```xml
<ClCompile Include="CAPE\YaraHarness.c" />
```
Replace with:
```xml
<ClCompile Include="CAPE\YaraHarness.c">
  <ExcludedFromBuild Condition="'$(Configuration)|$(Platform)'=='Release|x64'">true</ExcludedFromBuild>
</ClCompile>
<ClCompile Include="CAPE\YaraHarnessX.c">
  <ExcludedFromBuild>true</ExcludedFromBuild>
  <ExcludedFromBuild Condition="'$(Configuration)|$(Platform)'=='Release|x64'">false</ExcludedFromBuild>
</ClCompile>
```
(`YaraHarnessX.c` excluded everywhere except x64 Release; `YaraHarness.c`
excluded in x64 Release.)

---

## Step 3 — build + fix + test

### Build

```bat
msbuild capemon.sln /p:Configuration=Release /p:Platform=x64 /t:capemon
```

Expected first-time friction:
* **Missing `_x86.lib` symbol / arch mismatch** — you're linking `yara_x64.lib`
  into x64, fine; make sure you didn't cross the 32/64 libs.
* **`LNK2019` unresolved `bcrypt`/`ntdll`/etc.** — add the missing lib from the
  `native-static-libs` list to `<AdditionalDependencies>`.
* **`LNK4098 libcmt conflicts with use of other libs`** — you're building
  Release (`/MT` → `libcmt`) and the Rust lib is also `libcmt` (`+crt-static`).
  These should agree. If it complains about `libcmtd`, you accidentally touched
  a Debug block — revert it.
* **C compile errors in `YaraHarnessX.c`** — it's never been compiled. Likely
  suspects: a missing cast MSVC wants, `_strdup` needing `<string.h>` (already
  included), C89-vs-C99 declaration placement. Fix in place; the logic is a
  faithful port of `YaraHarness.c`.

### Rules

Delete stale caches so rules recompile fresh:
```bat
del <analyzer>\data\yara\capemon.yac
del <analyzer>\data\yara\capemon.yrx
```
Then confirm the corpus compiles under YARA-X:
```bat
yr compile <analyzer>\data\yara\*.yar     :: `yr` = yara-x CLI, `cargo install yara-x`
```
Fix rejects in the **CAPE rules repo**, not capemon. `grep -r 'import "magic"'`
the corpus — that module isn't built in.

### Regression checklist (run a couple of known samples through CAPE)

- [ ] First analysis run: log shows `YaraInit: Compiled N rule files` then
      `Compiled rules saved to ...capemon.yrx`. Second run: `Compiled rules
      loaded from ...capemon.yrx`. Delete/corrupt the file → clean recompile.
- [ ] A rule with `cape_options` containing `bpN=$str+off` sets the **same**
      breakpoints as a libyara build (diff `YaraScan hit:` / `YaraScan match:`
      lines and the resulting `bpN` config).
- [ ] `dump`, `coverage`, `clear` option keywords still act.
- [ ] `GetAddressByYara` internal rules still resolve — check the
      `RtlInsertInvertedFunctionTable 0x... LdrpInvertedFunctionTableSRWLock`
      line appears in the log, and WMI/`vDbgPrint` hook resolution still works.
- [ ] `ScanForRulesCanary` still trips on the `capemon` canary.
- [ ] Multi-threaded sample with JIT + unpacking active: **no crash / no hang**;
      scans on multiple threads all produce hits (this exercises the per-thread
      scanner + re-entrancy guard).
- [ ] `capemon_x64.dll` size delta is acceptable.

### Then repeat for Win32 Release

Same four edits in the `Release|Win32` block (line ~145): `CAPE_USE_YARA_X`,
`.\yara-x\include`, `$(ProjectDir)\yara-x\lib`, `libyara32.lib` → `yara_x32.lib`
+ system libs. Extend both `ExcludedFromBuild` conditions to also cover
`'Release|Win32'`. Build `/p:Platform=Win32`, re-run the checklist (32-bit target).

---

## Risks to watch during testing

* **Injection model.** wasmtime and Rust std both use TLS and one-time init.
  LoadLibrary injection: fine. If capemon's loader does manual mapping for some
  scenarios, watch for crashes on the first `YaraScan` (uninitialised Rust std /
  wasmtime TLS). `pulley` reduces but may not eliminate this.
* **Loader lock.** `YaraScan` can be called from DLL-notification / hook context.
  YARA-X allocates during scan; if that happens under the loader lock it can
  deadlock. libyara had the same exposure — compare behaviour, don't assume new.
* **`yrx_finalize` is intentionally never called** (see code comment) — it tears
  down process-wide wasmtime trap-handler state and would fight capemon's VEH.

---

## What to report back to continue

1. Did x64 Release build? Any `YaraHarnessX.c` compile fixes made (paste diffs).
2. Final `<AdditionalDependencies>` line (the resolved system-lib list).
3. `capemon_x64.dll` size before/after.
4. Regression checklist results — especially the multi-threaded no-crash item and
   the breakpoint-parity item.
5. Any rule-corpus rejects (list them; they’re fixed in the rules repo).
6. Whether to proceed to Win32 Release and/or tackle Debug (needs a second,
   non-`+crt-static` Rust build against `/MDd`).
