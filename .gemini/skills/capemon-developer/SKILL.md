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

## Systems Research, OS-Level Constraints & Absolute Fidelity Mandates
- **Verify Runtime & Injection Context:** Before utilizing C-language features, compiler directives, or libraries, you must thoroughly analyze the target execution context. For an injected monitoring DLL (like `capemon`), the library is loaded dynamically after process startup via `LoadLibrary`/`LdrLoadDll`.
- **Ban Static Thread Local Storage (`__declspec(thread)`):**
  *   *The System Constraint:* In Windows, static Thread Local Storage (`__declspec(thread)`) is allocated by the OS loader during process startup. It is highly unstable, buggy, or completely unsupported inside DLLs loaded post-startup.
  *   *The Mandate:* **NEVER use `__declspec(thread)` inside `capemon.dll` helper modules.** If a thread-local context or tracking state is required, you must **always** utilize the safe, dynamic Windows TLS APIs (`TlsAlloc`, `TlsGetValue`, `TlsSetValue`, `TlsFree`).
  *   *Refactor Rule:* Cleanly wrap dynamic TLS contexts in structures and expose them to helpers via preprocessor macros to keep changes microscopic, maintainable, and backward-compatible.
- **Rigorously Check Virtual Table Alignment:** When hooking dynamic COM interfaces (like WMI or scripting engines) or unmanaged class structures, you must account for virtual table offsets and compiler-specific virtual inheritance (which can shift offsets across OS/MSVC versions). Utilize Structured Exception Handling (SEH) blocks and pointer-validation probes (`IsBadReadPtr`-equivalent checks) to protect hooks from dynamic crashes.
  *   *Self-Propagating COM VTable Hooking:* If target COM interfaces (like WMI) are dynamically instantiated and lack standard unmanaged symbol exports (e.g., in modern Windows 10/11), implement a self-propagating chain: hook the creator interface (like `IWbemServices`), then intercept its returned objects (like `IEnumWbemClassObject`) to dynamically hook their vtables on-the-fly, decoupling the engine completely from compiler mangled symbols.
- **Ensure Absolute Behavioral & Parameter Probing Fidelity:**
  *   *The Evasion Vector:* Malware authors often execute "malformed/invalid" API queries (e.g., calling WMI methods with garbage property names, or passing invalid pointers) specifically to probe whether the API is real or a hooked mock. If the real Windows API would fail with a specific error (like `WBEM_E_NOT_FOUND`), but the sandbox hook silently corrects it, intercepts it, or returns success (`S_OK`), the malware instantly detects the mock and evades.
  *   *The Mandate:* When faking, spoofing, or filtering APIs, **always behave exactly as native Windows would.** If an invalid or bad query is passed, the hook must return the exact same native error codes and state transitions as the unhooked OS would. Implement strict property safelists and error-clamping verifications to allow bad-query probing to fail naturally, preserving indistinguishable behavioral fidelity.
  *   *Microarchitectural & Hardware Consistency:* When spoofing physical assets (like multiple processor cores, disks, or cache hierarchies), never return static, duplicate, or uniform configurations that represent physical impossibilities (such as having the exact same cache size across L1, L2, and L3 caches). Utilize stateless, deterministic pointer-address hashing (e.g., `(ULONG_PTR)_this >> 4 % N`) to scale and distribute simulated hardware structures with flawless microarchitectural realism.
- **Formulate Exhaustive Verification Plans:** A task is incomplete until behavior is verified under identical VM environments. Before optimizing hot-path parameters (like spin-retries, locks, or buffers), always check for re-entrancy, recursive thread calls, and stack-corrupting `va_list` lifecycles.
- **Ban Heap Allocations on Hot-Path Intercepts (Anti-Reentrancy Deadlocks):**
  *   *The System Constraint:* Intercepting system-critical functions (like virtual memory allocation, directory querying, etc.) means your hooks run in all threads of the process. If a hook callback executes a heap allocation (`malloc`, `free`, or `HeapAlloc`), and another thread holds the heap lock, it results in an unrecoverable **re-entrancy deadlock** that freezes the application.
  *   *The Mandate:* NEVER use heap allocations inside hook callbacks. If you need buffer management, utilize stack allocation, Small Buffer Optimization (SBO), or pre-allocated Thread Local Storage (TLS).
- **Strictly Respect Calling Conventions & Register Integrity:**
  *   *The System Constraint:* Windows APIs utilize strict compiler-defined calling conventions (`__stdcall`, `__fastcall`, `__cdecl`). Hook callbacks must preserve CPU registers and stack parameters with absolute precision.
  *   *The Mandate:* Always match the unhooked calling conventions and parameters exactly as defined in the unhooked Windows SDK. Never modify volatile registers (like `ECX`/`EDX` on x86, or `RCX`/`RDX` on x64) inside helper functions unless explicitly spoofing a return value, avoiding memory corruption and silent crashes.
- **Prevent Infinite Hook Recursion (Use Original Function Pointers):**
  *   *The System Constraint:* Calling hooked APIs inside a hook callback triggers infinite recursive call loops, causing stack overflows.
  *   *The Mandate:* If a hook callback needs to execute a system operation, **always** call the unhooked, original API function pointer (e.g., `Old_FunctionName()`) instead of the public export, ensuring completely safe and silent execution.
- **Hook Consolidation & Minimal Hook Footprint (CPU I-Cache Protection):**
  *   *The System Constraint:* Every new inline hook installed thrashes the CPU Instruction Cache (I-Cache), flushes pipelines, and increases the surface area for deadlocks, timing detection, and re-entrancy bugs.
  *   *The Mandate:* NEVER register a new inline hook if the target execution flow can be intercepted inside an existing core gateway hook. You must **always consolidate** filtering and spoofing logic (such as Registry/PCI Enum filters, and Hyper-V object blocklists) inside already-established gateways (like `NtOpenKey`, `NtEnumerateKey`, `NtCreateFile`, or `NtQueryValueKey`), preserving 100% of the VM's native hardware performance.
- **Surgical, Modular Pull Request Boundaries:**
  *   *The Mandate:* When implementing complex evasion bypasses (like those targeting `al-khaser` or `anticuckoo`), **always split your fixes into separate, isolated, and highly surgical branches and Pull Requests** (e.g., one branch for ACPI/GetSystemFirmwareTable, one for PCI Registry, and one for NtYieldExecution). Never consolidate unrelated features into a single PR, as modular reviews guarantee absolute architectural correctness and frictionless merges.

## Systems-Security Thinking & Hygiene Philosophy (Thinking Mandates)
When implementing or optimizing hooks, faking, or evasion bypasses, you must strictly adhere to the following **philosophical thinking mandates**:

- **Question Simple/Universal Bypasses (The Deadlock & Starvation Check):**
  *   Before implementing a simple bypass (like always force-returning `STATUS_SUCCESS` from `NtYieldExecution`), you must **actively simulate and question** the downstream consequences.
  *   *The Mandate:* Will blocking or skipping the original system call cause CPU starvation, infinite spinlocks, or deadlocks in multi-threaded programs or Windows system libraries? If so, you **must** execute the original system API first and only conditionally override the output return state to maintain absolute behavioral equivalence.
- **Identify and Correct Arch-Specific Fragility (The x64 Generalization Rule):**
  *   Always analyze if existing hacks or hotfixes are artificially restricted to a single architecture (such as `#ifndef _WIN64` or `#ifdef _X86_`).
  *   *The Mandate:* Question why the restriction exists. If the underlying evasion vector applies equally to x64, you must refactor and generalize the fix to be completely cross-platform, robust, and compile-safe under both 32-bit and 64-bit targets.
- **Rigorously Preserve Historical Research Citations & Comments:**
  *   Code is not just logic; it is a repository of historical malware-analysis discoveries and security intelligence.
  *   *The Mandate:* **NEVER delete or silently omit existing developer comments containing malware hashes, CVE references, or GitHub repository links (such as Pikabot sample references).** When refactoring or replacing code blocks, always migrate and preserve these citations cleanly to keep the codebase highly traceable, educational, and respectful of the original research community.

## The Multi-Perspective Sandbox Planning (MPSP) Framework
When designing any feature, fix, or spoofing improvement inside `capemon`, you must run your proposal through the **four competing developer personas**:

```
           +-----------------------------------------+
           |       1. THE OS / KERNEL DEVELOPER      |
           |   (API Specs, Failures, OS Internal Use)|
           +--------------------+--------------------+
                                |
                                v
           +--------------------+--------------------+
           |     2. THE MALWARE DEVELOPER (Adversary) |
           |   (Probing traps, timings, signatures)  |
           +--------------------+--------------------+
                                |
                                v
           +--------------------+--------------------+
           |      3. THE CAPEMON DEVELOPER (Monitor) |
           |  (Reentrancy, Consolidation, Overhead)  |
           +--------------------+--------------------+
                                |
                                v
           +--------------------+--------------------+
           |      4. THE SECURITY ANALYST (User)     |
           |   (Logger completeness, noise limits)   |
           +-----------------------------------------+
```

### **The Socratic Questions to Ask During Planning:**

#### **Persona 1: The OS / Kernel Developer (The Platform)**
- *What is the exact API specification?* What are the legal, illegal, and undocumented return values/structures?
- *How does Windows internally use this API?* Do core system libraries (like `ntdll` or `kernel32`) call this API for thread scheduling, memory management, or critical locks/synchronization?
- *What is the impact of a static override?* If I force-return a value (like `STATUS_SUCCESS`), does it break cooperative multi-threading, cause infinite spinlock loops, or trigger CPU core starvation?

#### **Persona 2: The Malware Developer (The Adversary)**
- *How can I detect or exploit this monitor hook?* Does the hook read or write to watched memory (`MEM_WRITE_WATCH`), revealing its footprint?
- *What side-effects does my check cause?* If I execute an invalid or malformed query, does the hook silently correct it, or does it fail naturally as native Windows would?
- *Can I bypass this via alternate paths?* If the user-mode exports are hooked, can I execute direct system calls, query unmanaged vtables, or query registry nodes?

#### **Persona 3: The Capemon/Sandbox Developer (The Monitor)**
- *Can this be consolidated?* Do we already hook a central gateway API (like `NtOpenKey` or `NtCreateFile`) that we can append our filters into, instead of installing a new trampoline?
- *Is this hot-path safe?* Does this callback allocate memory on the heap (triggering re-entrancy deadlocks under loader locks), or does it use safe stack buffers (SBO)?
- *Is it cross-platform (x86/x64) safe?* Does it handle 32-bit stack passing and 64-bit register conventions seamlessly?

#### **Persona 4: The Security Analyst (The User)**
- *What are we logging?* Does the log record exact argument names, values, and states to help construct an accurate process behavior timeline?
- *Is it noise-free?* Does the hook have logging limits (e.g., logging a maximum of 20 exceptions or debugger presence queries) to prevent infinite log expansion?
