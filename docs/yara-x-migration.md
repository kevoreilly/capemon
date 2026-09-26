# YARA-X backend for the in-monitor scanner

Status: **work in progress / opt-in**. libyara remains the default.

capemon's in-monitor YARA scanning lives entirely behind `CAPE/YaraHarness.h`
(7 functions + the `NameByAddress` struct). This change adds a second
implementation of that same interface, `CAPE/YaraHarnessX.c`, built against
[YARA-X](https://github.com/VirusTotal/yara-x) instead of libyara. Exactly one
backend is compiled in, selected by the `CAPE_USE_YARA_X` preprocessor define.

Nothing outside the harness changes: every caller (`hook_clr.c`, `Trace.c`,
`CAPE.c`, `hooks.c`, `capemon.c`, ...) keeps calling `YaraScan`,
`GetAddressesByYara`, etc. unchanged.

---

## What is in the tree now

| Path | Purpose |
|---|---|
| `CAPE/YaraHarness.c` | libyara backend (unchanged, still the default) |
| `CAPE/YaraHarnessX.c` | **new** — YARA-X backend, identical public API |
| `CAPE/YaraHarness.h` | `#include "yara.h"` is now skipped when `CAPE_USE_YARA_X` is set |
| `yara-x/include/yara_x.h` | vendored YARA-X C API header (v1.20.0) |
| `docs/yara-x/bin/{x32,x64}/` | prebuilt `yara_x_capi.dll` + import lib + PDB — this is what `capemon.vcxproj` actually links/loads today (see `docs/yara-x/readme.md`); **Step 1 below (a static lib in `yara-x/lib/`) is an alternative build path that is not currently wired into the project** |

The `yara-x/` layout deliberately mirrors `libyara/` (`include/` + `lib/`).

---

## Behavioural parity notes

* `cape_options` string metadata drives dynamic config exactly as before;
  `$pattern` references inside option lines are resolved to matched offsets via
  `ParseOptionLine`.
* Pattern identifiers are normalised to a leading `$` (YARA-X already returns
  `$name`, so this is normally a no-op) so option-line matching is unchanged.
* **Compiled-rule cache uses a different filename: `capemon.yrx`** (not
  `capemon.yac`). The serialized blob format differs and is locked to the exact
  YARA-X version; a stale/incompatible cache is detected on load and the rules
  are recompiled from `data/yara/*.yar`.
* YARA-X scanners are single-threaded, stateful objects. The backend keeps **one
  `YRX_SCANNER` per thread** (the `YRX_RULES` object is shared, which YARA-X
  explicitly supports) plus a per-thread re-entrancy guard so a scan triggered
  from inside a match callback is skipped rather than corrupting scanner state.
* `yrx_finalize()` is intentionally **not** called at shutdown — it tears down
  process-wide wasmtime exception-handler state and is unsafe while capemon's own
  VEH and debugger are installed. capemon lives for the process lifetime anyway.
* Compiler flags: `YRX_RELAXED_RE_SYNTAX | YRX_ENABLE_CONDITION_OPTIMIZATION`.
  Relaxed regex syntax maximises compatibility with the libyara-era rule corpus.

---

## Step 1 (alternative) — produce the YARA-X static libraries

> The project as committed links the **dynamic** `yara_x_capi.dll` prebuilt
> under `docs/yara-x/bin/{x32,x64}/` (see `docs/yara-x/readme.md` for how
> those were built). The static-lib path below is kept for reference/rollback
> to a statically-linked build; it requires redoing Step 2 to point back at
> `yara-x/lib/yara_xNN.lib` and the transitive system libs it needs.

Requires a Rust toolchain + [`cargo-c`](https://github.com/lu-zero/cargo-c) on a
machine with the MSVC build tools.

```bat
rustup target add x86_64-pc-windows-msvc i686-pc-windows-msvc
cargo install cargo-c

set RUSTFLAGS=-C target-feature=+crt-static

:: 64-bit
cargo cinstall -p yara-x-capi --release ^
  --target x86_64-pc-windows-msvc ^
  --library-type staticlib ^
  --no-default-features --features pe,dotnet,math,hash,string,console,elf,macho ^
  --destdir out64 --prefix /

:: 32-bit
cargo cinstall -p yara-x-capi --release ^
  --target i686-pc-windows-msvc ^
  --library-type staticlib ^
  --no-default-features --features pe,dotnet,math,hash,string,console,elf,macho ^
  --destdir out32 --prefix /
```

Then copy the artefacts into the repo, renamed per-arch like the libyara libs:

```
out64\lib\yara_x_capi.lib   ->  yara-x\lib\yara_x64.lib
out32\lib\yara_x_capi.lib   ->  yara-x\lib\yara_x32.lib
```

Keep `yara-x/include/yara_x.h` in sync with the version the libs were built from
(currently v1.20.0). The serialized `capemon.yrx` cache is only valid for the
exact version it was produced with.

Notes:
* `+crt-static` makes the Rust lib link the **static** CRT (`libcmt`), matching
  capemon's `/MT` Release configs. This conflicts with `/MTd` in **Debug**
  configs — see Step 3.
* Dropping `--features` you don't need (`magic`, `lief`, `time`) keeps the lib
  smaller. `pe` + `dotnet` are the important ones for CAPE rules.
* `cargo-c` prints the transitive system libraries the static lib needs (into a
  `.pc` file). Expect roughly: `ntdll userenv bcrypt advapi32 ws2_32 kernel32`.

---

## Step 2 — project changes (`capemon.vcxproj`)

> This describes the static-lib wiring matching Step 1 above. The
> **currently-committed** `Release|x64` block instead links
> `docs\yara-x\bin\x64\yara_x_capi.dll.lib` (dynamic import lib, no
> `ntdll`/`userenv`/`bcrypt`/`advapi32`) and has a `PostBuildEvent` that copies
> `yara_x_capi.dll` next to the built `capemon_x64.dll` so it can be loaded at
> runtime. Only `Release|x64` is enabled today; `Win32` is not yet wired up.

For each of the four `ItemDefinitionGroup` blocks (Debug/Release × Win32/x64):

1. **PreprocessorDefinitions** — add `CAPE_USE_YARA_X`.
2. **AdditionalIncludeDirectories** — `.\libyara\include` → `.\yara-x\include`.
3. **AdditionalLibraryDirectories** — `$(ProjectDir)\libyara\lib` → `$(ProjectDir)\yara-x\lib`.
4. **AdditionalDependencies**:
   * Win32: `libyara32.lib` → `yara_x32.lib;ntdll.lib;userenv.lib;bcrypt.lib;advapi32.lib`
   * x64:   `libyara64.lib` → `yara_x64.lib;ntdll.lib;userenv.lib;bcrypt.lib;advapi32.lib`
   * (`crypt32.lib` was only needed by libyara's hash module — safe to drop once
     libyara is gone; harmless to leave.)

Add the source file to the project (once, applies to all configs):

```xml
<ClCompile Include="CAPE\YaraHarnessX.c" />
```

and exclude the libyara backend from the build (keep the file for now):

```xml
<ClCompile Include="CAPE\YaraHarness.c">
  <ExcludedFromBuild>true</ExcludedFromBuild>
</ClCompile>
```

(Or, cleaner: put both `<ClCompile>` entries under `Condition`s keyed on a
`$(UseYaraX)` MSBuild property so a single switch flips the whole thing.)

---

## Step 3 — Debug configuration

Rust's `+crt-static` gives a release static CRT. In capemon **Debug**
(`/MTd` → `libcmtd`) the linker will report `LNK4098: defaultlib 'libcmt'
conflicts`. Options, easiest first:

1. **Only enable `CAPE_USE_YARA_X` in Release** (Debug keeps libyara). capemon
   ships Release; this is the recommended starting point.
2. Build a second Rust lib without `+crt-static` and link Debug capemon against
   the dynamic CRT (`/MDd`) — changes capemon's CRT model, invasive.
3. `/NODEFAULTLIB:libcmt` + accept mixing — fragile, not recommended.

---

## Step 4 — rules

* Delete any stale `data/yara/capemon.yac` and `capemon.yrx`.
* Run the full CAPE rule corpus through the `yara-x` CLI:
  `yr fmt --check` / `yr compile data/yara/*.yar` and fix rejects. YARA-X is
  stricter (more warnings-as-errors, a few removed constructs); most rules pass
  unchanged. Track fixes in the CAPE rules repo, not here.
* `pe`, `dotnet`, `math`, `hash`, `string`, `console`, `elf`, `macho` modules are
  built in (per the feature list in Step 1). `magic` is **not** — grep the corpus
  for `import "magic"` before shipping.

---

## Step 5 — regression test

Build Release x86 **and** x64. Then, against known samples:

* [ ] `yarascan=1` — a rule with `bpN=$str+off` style `cape_options` sets the
      same breakpoints as the libyara build (diff the debug log).
* [ ] `dump`, `coverage`, `clear` option keywords still act.
* [ ] `GetAddressByYara`/`GetAddressesByYara` still resolve
      `RtlInsertInvertedFunctionTable`, the `WMI_*` and `vDbgPrint*` internal
      rules (check the `YaraInit` / hook-resolution log lines).
* [ ] `ScanForRulesCanary` still trips on the `capemon` canary rule.
* [ ] Multi-threaded target with JIT + unpacking active: no crash/hang, scans on
      different threads all produce hits.
* [ ] First run compiles + writes `capemon.yrx`; second run loads it; corrupting
      the file forces a clean recompile.

---

## Rollback

Everything is behind `CAPE_USE_YARA_X` + one extra source file. Remove the define,
re-include `YaraHarness.c`, restore the four vcxproj blocks. `libyara/` is left
untouched until the switch is considered permanent, at which point delete
`libyara/`, `CAPE/YaraHarness.c`, and the `#ifndef CAPE_USE_YARA_X` guard in the
header.
