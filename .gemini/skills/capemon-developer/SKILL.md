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

- **Never use `__declspec(thread)` for data structures in post-loaded DLLs.** Static TLS is allocated at process load time and causes crashes/corruption when DLLs are injected post-startup. Use dynamic Windows TLS APIs (`TlsAlloc`, `TlsGetValue`, `TlsSetValue`, `TlsFree`) for actual context data.
  - *Pointer caching is safe:* `static __declspec(thread) ctx_t* g_tls_cache = NULL;` with NULL-fallback to `TlsGetValue()` is a valid performance optimization (avoids repeated API calls on hot path).
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
- **Match calling conventions for COM methods:** x86 COM methods (e.g., `ICorJitInfo::getMethodName`) use `__thiscall` where `this` is passed in `ECX`, not `__stdcall`. Using wrong convention causes stack imbalance: callee cleans wrong stack frame → ESP corruption → crash. On x86, typedef function pointers as `__thiscall`; on x64, use `__fastcall`. Always validate vtable pointers and method parameters with `IsBadReadPtr` before calling CLR/COM vtables.

### Pull Request Discipline

- **Split unrelated fixes into separate surgical PRs.** Don't consolidate evasion fixes for al-khaser, anticuckoo, ACPI, PCI, and NtYieldExecution in one PR. Modular reviews guarantee correctness and frictionless merges.

### Code Preservation & Intellectual Debt

- **Never delete comments with research citations.** Developer comments contain malware hashes, CVE references, and GitHub repository links. When refactoring, migrate citations cleanly to keep the codebase traceable and educational.

## Common Crash Patterns & Prevention

### Crash 1: Static TLS Corruption in Post-Loaded DLLs

**Symptoms:** Immediate crash or stack corruption during early logging or thread-local operations.

**Root Cause:** Using `__declspec(thread)` to store data structures (not pointers) in a DLL loaded post-startup. Static TLS is allocated by the OS loader at process init; dynamic injection skips this initialization, leading to memory corruption.

**Example:** `static __declspec(thread) bson g_bson[1];` → **CRASH**

**Fix:** Use dynamic Windows TLS APIs for actual data:
```c
// g_bson → stored via TlsSetValue(g_bson_tls_index, context)
// Macro accessor: #define g_bson (ctx ? ctx->g_bson : NULL)
// Fallback: IsBadReadPtr checks before access
```

### Crash 2: Calling Convention Mismatch (`__thiscall` vs `__stdcall`)

**Symptoms:** ESP corruption, immediate crash, or delayed stack corruption inside hooked COM methods.

**Root Cause:** x86 COM methods (e.g., `ICorJitInfo::getMethodName`) use `__thiscall` (this in ECX), not `__stdcall`. Wrong convention = arguments on stack instead of registers → callee cleans wrong frame size → ESP corrupted.

**Example:** `typedef const char* (__stdcall *fn)(PVOID _this, ...)` on x86 → **CRASH**

**Fix:** Architecture-specific function pointers:
```c
#if defined(_M_IX86)
typedef const char* (__thiscall *fn)(PVOID _this, PVOID ftn, ...);
#else
typedef const char* (__fastcall *fn)(PVOID _this, PVOID ftn, ...);
#endif
```

### Crash 3: Heap Allocation Under Lock (Re-entrancy Deadlock)

**Symptoms:** Process freezes, all threads block, no exception. Debugger shows one thread holds heap lock, another waits on hook callback that needs heap alloc.

**Root Cause:** Hook runs in all threads. If hook allocates heap (`malloc`, `HeapAlloc`), and another thread holds the heap lock, deadlock. Cannot be caught by SEH; freezes the process.

**Example:**
```c
void hook_callback() {
    EnterCriticalSection(&g_mutex);
    char *buf = malloc(256);  // ← DEADLOCK if another thread holds heap lock
}
```

**Fix:** Use stack allocation or pre-allocated TLS only:
```c
void hook_callback() {
    char buf[256];  // stack: always safe
    // or
    thread_ctx_t *ctx = TlsGetValue(g_tls_index);  // pre-allocated
}
```

## Synchronization & Lock Safety

- **Use critical sections only for slow-path operations.** Locks block all threads in the process. Minimize hold time; never call complex functions (API calls, allocations) inside critical sections.
- **Establish a global lock ordering.** If hook A acquires `lock1` then `lock2`, every other code path must acquire locks in the same order. Document lock hierarchy comments in code.
- **Never nest locks on the same thread.** If you hold `g_mutex`, don't try to acquire it again on the same thread. Use `TryEnterCriticalSection` with fallback logic, not blocking re-entry.
- **Protect shared state, not code regions.** Only lock access to shared memory (counters, caches, vtables), not entire operations. Release the lock immediately after modifying shared data.

## Stack-Based Allocation (SBO) Pattern

**Rule:** In hook callbacks, always use **stack allocation**, not heap.

**Why:** Hooks run in all threads. If a callback does `malloc()` and another thread holds the heap lock, re-entrancy deadlock (process freeze, no exception).

**Pattern:**
```c
// Good: stack-based, bounded
static void log_value(const char *name, int value) {
    char buf[256];  // bounded stack
    snprintf(buf, sizeof(buf), "%s=%d", name, value);
}

// Bad: heap allocation in hook
void hook_callback() {
    char *buf = malloc(1024);  // ← DEADLOCK risk
}

// Good: Small Buffer Optimization (SBO)
// Pre-allocate thread-local context once, reuse in all callbacks
thread_ctx_t *ctx = TlsGetValue(g_tls_index);  // cached pointer
if (ctx) {
    snprintf(ctx->buf, sizeof(ctx->buf), ...);  // reuse pre-allocated
}
```

**Verification:** Before committing hook code, grep for `malloc`, `calloc`, `HeapAlloc` inside hook callbacks. If found, refactor to stack or pre-allocated TLS.

## Design Decision & Thinking Frameworks

### Pre-Implementation Checklist

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

### Four-Persona Challenge Framework

Challenge every hook/bypass proposal by asking:

| Persona | Key Questions |
|---------|---|
| **OS/Kernel Dev** | What's the exact API spec? Does this break multi-threading or cause CPU starvation? |
| **Malware Author** | How do I detect this mock? Via invalid probes, timing, or memory watches? Can I bypass via direct syscalls? |
| **Capemon Dev** | Should this consolidate into an existing hook? Is it re-entrancy safe? x86/x64 compatible? |
| **Security Analyst** | Is logging complete (names, values, state)? Are there safeguards against infinite expansion? |

### Critical Thinking Mandates

- **Deadlock & Starvation Check:** Before blocking/skipping any syscall, simulate downstream consequences. Will multi-threaded programs or Windows libraries deadlock or starve?
- **Arch Generalization Rule:** If code is `#ifdef _WIN64` or `#ifdef _X86_`, question why. If the fix applies equally to both, refactor to support both cleanly.
- **Historical Debt Preservation:** Never delete comments with malware hashes, CVEs, or repo links. These are research artifacts; migrate them cleanly during refactors.

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

