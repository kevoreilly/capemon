---
name: capemon-developer
description: Expert capability for navigating, modifying, and extending the capemon malware monitoring codebase. Includes deep knowledge of Windows API hooking, PE structures, and the CAPEv2 sandbox architecture.
---

# Capemon Skills

`capemon` is a sophisticated monitoring and instrumentation engine designed for malware analysis, configuration extraction, and payload recovery. It acts as the core injection component for the CAPEv2 sandbox.

## Core Capabilities

### 1. API Hooking & Monitoring
`capemon` implements an extensive hooking engine derived from `cuckoomon-modified`, providing deep visibility into application behavior across multiple subsystems:
- **Process & Thread Management:** Monitoring creation, termination, and manipulation of processes and threads.
- **File System Operations:** Tracking file creation, deletion, reading, and writing.
- **Registry Activity:** Capturing configuration changes and persistence mechanisms.
- **Network Communication:** Intercepting socket operations, DNS queries, and high-level protocol activity (HTTP, etc.).
- **Cryptography:** Extracting keys and monitoring encryption/decryption routines.
- **Synchronization & Services:** Monitoring mutexes, events, and Windows Service interactions.
- **Windows Management Instrumentation (WMI):** Intercepting WMI queries used for anti-analysis or reconnaissance.
- **Scripting Engines:** Specific hooks for VBScript and other language runtimes.

### 2. Debugging & Tracing
`capemon` implements a powerful in-process debugger independent of Windows debugging interfaces, but harnessing the capabilities of the processor:
- **Hardware breakpoints:** Four breakpoints bp0-bp3 that can be set on execute, read or write
- **Software breakpoints:** Unlimited INT3 or 'CC' breakpoints overwriting instruction byte
- **Single-step:** Tracing allows instruction-level capture enhanced with configurable step-over, trace-length, register changes, function names, strings & more
- **Actions:** Configurable actions allow control flow manipulation with skipped or taken jumps, arbitrary register changes or jumps, string capture, dumps, scans & more
- **Programmable:** Debugger configurable either on submission with simple text options or via dynamic YARA signature scans during unpacking or detonation
- **Integration:** Hooking engine integrated with optional behavior log output & breakpoints set on return from hooked APIs (break-on-return)
- **Stealth:** Debugger does not rely upon Windows interface and thus evades detection by a slew of interface-related indicators, with additional stealth from hook-based protections

### 3. Automated Unpacking
'capemon' implements a powerful unpacking engine using a combination of techniques
- **Memory region tracking:** Regions of memory revealed through indicators of execution, allocation or protection are tracked
- **Early capture:** Multiple possible triggers allow payload capture at earliest moment often resulting in working unpacked samples
- **Injection capture:**: Strong coverage of injection techniques for inter-process payload capture
- **PE unmapping:** Integrated Scylla engine allows capture of memory or file-mapped PE images in memory
- **Shellcode dumping:** Shellcode * non-PE regions equally captured as payloads
- **Import Reconstruction:** Repairing Import Address Tables (IAT) to create functional dumped executables.
- **AMSI Dumping:** Intercepting and dumping buffers passed to the Antimalware Scan Interface (AMSI).

### 4. Config Extraction
Automated Static & Dynamic malware configuration extraction relies on 'capemon' capabilities
- **Static extraction:** Typically reliant upon capemon's unpacking or process dump capture before static parsing
- **Dynamic extraction:** When parser implementation is onerous, dynamic capture of decrypted configs can be performed by debugger via YARA signature

### 5. YARA integration
Integration of YARA for in-memory scanning
- **Dynamic configuration:** Sandbox configuration such as hooking exclusions or options implemented during detonation
- **Debugger programming:** Precise dydnamic breakpoint address resolution using YARA signatures & cape-specific metadata
- **Unpacking engine integration:** Dynamic scanning of all memory regions prior to unpacking capture
- **Function resolution:** Allows dynamic address resolution for APIs or functions for hooking or other purposes

## Technical Foundations
- **Platform:** Windows (x86 and x64).
- **Hooking Method:** Inline hooking of Win32 and Native APIs (NTAPI).
- **Debugger:** Native in-process 'self' debugging utilising minimal OS interfaces & hardware capabilities (breakpoint, single-step)
- **Dependencies:**
    - `distorm` for instruction decoding.
    - `libyara` for pattern matching.
    - `Scylla` for PE reconstruction.
    - `bson` for data serialization.

## Engineering & Documentation Mandates
- **Always update `@docs/configuration.md`:** Whenever a new configurable option is introduced to the engine (such as `log-format`, `sleep-skip-seconds`, etc.), you must immediately append its documentation details to the appropriate table inside the configuration reference document to ensure the user and the system documentation are fully up-to-date.

## Critical System Constraints & OS-Level Design Rules

**Verify Injection Context:** `capemon` is dynamically loaded post-startup via `LoadLibrary`/`LdrLoadDll`, not during process initialization. This context affects every C feature, compiler directive, and dependency you choose.

### Memory & Thread Locality

- **NEVER use `__declspec(thread)` for data structures.** Static TLS allocated by the OS loader is unstable/unsupported inside post-loaded DLLs. Always use dynamic Windows TLS APIs (`TlsAlloc`, `TlsGetValue`, `TlsSetValue`, `TlsFree`).
  - *Exception:* Cache pointers to TLS contexts only: `static __declspec(thread) ctx_t* g_tls_cache = NULL;` with NULL-safety fallback.
- **NEVER allocate heap memory in hot-path hooks.** A hook running in all threads can deadlock if another thread holds the heap lock. Use stack allocation, Small Buffer Optimization (SBO), or pre-allocated TLS instead.
- **NEVER call hooked APIs inside hook callbacks.** Recursion causes stack overflow. Always call the original function pointer (e.g., `Old_FunctionName()`).

### Hook Architecture

- **Consolidate hooks inside existing gateways.** Don't install a new hook if filtering logic can go into `NtOpenKey`, `NtCreateFile`, or other core APIs already hooked. Every new hook thrashes the I-Cache and increases deadlock surface.
- **Respect calling conventions exactly.** Match Windows SDK signatures: `__stdcall`, `__fastcall`, `__cdecl`. Don't modify volatile registers (`ECX`/`EDX` on x86, `RCX`/`RDX` on x64) unless spoofing a return value.

### Behavioral Fidelity

- **Match Windows error behavior exactly.** If native Windows returns `WBEM_E_NOT_FOUND` for a bad query, the hook must too. Malware probes for mock behavior by sending invalid input; mismatched responses reveal the sandbox.
- **Avoid static hardware configs.** Don't spoof the same L1/L2/L3 cache size, or return identical core counts. Use stateless deterministic hashing (e.g., `(ULONG_PTR)_this >> 4 % N`) to simulate realistic hardware variation.
- **Verify under identical test VMs.** Before optimizing spin-retries, locks, or buffers, verify re-entrancy, recursive thread calls, and `va_list` lifecycles on the target environment.

### COM & Virtual Table Hooking

- **Account for vtable offset variance.** COM interfaces across OS versions and MSVC versions have shifting offsets. Protect with SEH blocks and pointer-validation checks (`IsBadReadPtr`-like probes).
- **Use self-propagating COM chains.** For dynamically-instantiated interfaces without symbol exports (Windows 10/11), hook the creator (e.g., `IWbemServices`), then intercept returned objects (e.g., `IEnumWbemClassObject`) to hook their vtables on-the-fly.

### Pull Request Discipline

- **Split unrelated fixes into separate surgical PRs.** Don't consolidate evasion fixes for al-khaser, anticuckoo, ACPI, PCI, and NtYieldExecution in one PR. Modular reviews guarantee correctness and frictionless merges.

### Code Preservation & Intellectual Debt

- **Never delete comments with research citations.** Developer comments contain malware hashes, CVE references, and GitHub repository links. When refactoring, migrate citations cleanly to keep the codebase traceable and educational.

## Design Decision Checklist

Before implementing any hook, bypass, or feature, verify:

**API Fidelity:**
- Exact Windows SDK specification (legal, illegal, undocumented return values)?
- Does the hook break multi-threading, cause spinlocks, or starve CPU cores?
- Will malware detect this as a mock (invalid input probing, timing, memory watches)?

**Architecture & Performance:**
- Can this consolidate into an existing hook (e.g., `NtOpenKey`), or does it need a new trampoline?
- Is the callback re-entrancy safe? (heap-safe, stack buffers only, TLS-backed)
- Does it handle x86/x64 calling conventions cleanly?

**Logging & Completeness:**
- What gets logged—exact argument names, values, state transitions for accurate behavior timeline reconstruction?
- Is the log noise-free? (Set caps, e.g., max 20 exception queries, to prevent expansion attacks)

## Build & Compilation Guide

### 1. Locating MSBuild
On a standard Windows development machine, MSBuild may not be present in the global `PATH`. You can locate it using PowerShell by running a query over the standard Microsoft Visual Studio or Build Tools installation directories:

```powershell
Get-ChildItem -Path "C:\Program Files", "C:\Program Files (x86)" -Filter "MSBuild.exe" -Recurse -ErrorAction SilentlyContinue | Select-Object -ExpandProperty FullName
```

Typical installation paths include:
* **Visual Studio 2022 Build Tools (32-bit/64-bit host):**
  `C:\Program Files (x86)\Microsoft Visual Studio\2022\BuildTools\MSBuild\Current\Bin\MSBuild.exe`
* **Visual Studio 2022 Community Edition:**
  `C:\Program Files (x86)\Microsoft Visual Studio\2022\Community\MSBuild\Current\Bin\MSBuild.exe`

### 2. Compilation Targets and Toolset Overrides
The `capemon` solution specifies the legacy Visual Studio 2017 (`v141`) platform toolset. If your local build system only has Visual Studio 2022 (`v143`) installed, you can compile successfully by dynamically overriding the platform toolset and disabling Whole Program Optimization (`LTCG` / Link-Time Code Generation) to prevent linker mismatches against precompiled static `.lib` dependencies (like `libyara`).

#### Compiling Win32 (x86) Release Target:
```powershell
$msbuild = "C:\Program Files (x86)\Microsoft Visual Studio\2022\BuildTools\MSBuild\Current\Bin\MSBuild.exe"
& $msbuild /m /p:Configuration=Release /p:Platform=Win32 /p:PlatformToolset=v143 /p:WholeProgramOptimization=false capemon.sln
```

#### Compiling x64 (64-bit) Release Target:
```powershell
$msbuild = "C:\Program Files (x86)\Microsoft Visual Studio\2022\BuildTools\MSBuild\Current\Bin\MSBuild.exe"
& $msbuild /m /p:Configuration=Release /p:Platform=x64 /p:PlatformToolset=v143 /p:WholeProgramOptimization=false capemon.sln
```

