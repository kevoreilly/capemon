# YARA-X Compilation & Wasmtime Pulley Integration Guide

This guide details the internal compilation architecture of YARA-X condition evaluation, explains the relationship between the JIT compiler and the Pulley interpreter within `wasmtime`, details how to avoid JIT execution memory constraints (executable memory pages), lists instructions for multi-architecture builds, and details how to generate and use debug symbols.

---

## Technical Background: YARA-X Wasm Runtime

To achieve maximum performance during scanning, YARA-X compiles YARA rule conditions into WebAssembly (Wasm) bytecode on the fly. 

To execute this bytecode, YARA-X integrates **Wasmtime** as its execution engine. However, executing unmanaged WebAssembly bytecode on a host machine requires translating it into a format the engine can execute, which introduces specific architectural constraints.

---

## The JIT Compiler vs. Pulley Interpreter

Wasmtime offers two primary methods of executing WebAssembly bytecode:

### 1. Cranelift JIT Compilation (Default)
By default, Wasmtime uses the **Cranelift** compiler backend to compile WebAssembly bytecode directly into native host machine CPU instructions (e.g., x86_64, AArch64) at runtime.
*   **Performance:** Maximum execution speed.
*   **Security Constraint:** Requires the allocation of executable memory pages (e.g., `VirtualAlloc` with `PAGE_EXECUTE_READWRITE` or `PAGE_EXECUTE_READ`), which may be restricted or prohibited in secured sandbox environments, containers, or protected processes.

### 2. Pulley Bytecode Interpreter
Wasmtime includes the **Pulley** interpreter—a highly portable, virtual-machine-based software interpreter.
*   **Security Advantage:** Because Pulley executes bytecode via a software interpreter loop, **no native machine instructions are generated or executed from dynamically allocated memory pages**. All code runs out of standard, non-executable read/write memory pages, eliminating JIT execution constraints and complying with strict security policies.
*   **Portability:** Runs on any hardware architecture supported by Rust, even those without native Cranelift JIT backends.

---

## The Compilation Trap: Why Cranelift is Required for Pulley

When attempting to build YARA-X with Pulley to reduce binary size or strip JIT capabilities, it is a common mistake to completely disable the `"cranelift"` feature of the `wasmtime` dependency in `lib/Cargo.toml`. 

**This results in immediate compiler errors (e.g., undeclared associated functions like `Module::from_binary`).**

### Architectural Root Cause
1.  **Pulley is not a direct WASM interpreter.** Wasmtime's Pulley VM does not interpret raw, standard WebAssembly bytecode on the fly. Instead, WebAssembly bytecode must be compiled into **Pulley interpreter bytecode** (an optimized virtual machine instruction format).
2.  **Cranelift is still the compiler.** The **Cranelift** backend is the compiler responsible for translating standard WebAssembly bytecode into Pulley interpreter bytecode.
3.  **No Compiler = No Execution:** If `"cranelift"` is completely disabled, Wasmtime compiles with **zero compiler backends**. As a result, Wasmtime strips all dynamic rule-compilation APIs (such as `Module::from_binary`, `Module::new`, `Config::cranelift_opt_level`, and `Engine::unload_process_handlers`).
4.  **The Solution:** You **must retain** `"cranelift"` and `"runtime"` features in your `lib/Cargo.toml` dependencies. The compiler backend is required to translate the generated rules into Pulley format, but the execution remains 100% compliant with non-executable page sandboxing.

---

## Pre-Compiled & Integrated Binaries

Prerelease-ready, size-optimized binaries built with Pulley and Link-Time Optimization (LTO) have been generated and integrated into this project's workspace for immediate linking or loading:

*   **x64 (64-bit Target):** Located under `docs/yara-x/bin/x64/`
    *   `yara_x_capi.dll` (Approx. 20.2 MB) — Standard Windows x64 DLL.
    *   `yara_x_capi.dll.lib` — Import library for compilation linkage.
    *   `yara_x_capi.pdb` — Full debug symbols (PDB format).
*   **x32 (32-bit Target):** Located under `docs/yara-x/bin/x32/`
    *   `yara_x_capi.dll` (Approx. 16.8 MB) — Standard Windows x32 DLL.
    *   `yara_x_capi.dll.lib` — Import library for compilation linkage.
    *   `yara_x_capi.pdb` — Full debug symbols (PDB format).

---

## Compilation Guide: Multi-Architecture Build Commands

Use the following commands inside the `yara-x` directory to build the size-optimized release binaries manually. If `cargo` is not in your global system `PATH`, locate it at `C:\Users\Doome\.cargo\bin\cargo.exe`.

### 1. Compile for x64 (64-bit Release with Pulley)
```powershell
& 'C:\Users\Doome\.cargo\bin\cargo.exe' build -p yara-x-capi --profile release-lto --target x86_64-pc-windows-msvc --features pulley
```

### 2. Compile for x32 (32-bit Release with Pulley)
```powershell
& 'C:\Users\Doome\.cargo\bin\cargo.exe' build -p yara-x-capi --profile release-lto --target i686-pc-windows-msvc --features pulley
```

---

## Developer Debugging Guide: How to Compile with Debug Symbols

During development or troubleshooting, developers may need to inspect the C-API, check call stacks, or run a debugger (like WinDbg, VS Debugger, or `cdb.exe`).

### Option A: Standard Debug Build (Recommended for active debugging)
To produce a fully unoptimized build containing full line information, function scopes, and variables with zero compiler inlining:
```powershell
# For 64-bit Debug:
& 'C:\Users\Doome\.cargo\bin\cargo.exe' build -p yara-x-capi --target x86_64-pc-windows-msvc --features pulley

# For 32-bit Debug:
& 'C:\Users\Doome\.cargo\bin\cargo.exe' build -p yara-x-capi --target i686-pc-windows-msvc --features pulley
```
*   **Debug Symbols:** This creates `yara_x_capi.pdb` and `yara_x_capi.dll` inside `target/x86_64-pc-windows-msvc/debug/`. Because optimization is turned off (`opt-level = 0`), you can set breakpoints and inspect all local variables natively.

### Option B: Optimized Release Build with Debug Symbols
If you need to analyze performance bottlenecks or debug issues that only manifest under optimized builds, you can force the release profile to retain full debug symbols. 

Add the following to the workspace `Cargo.toml` in `yara-x` (or pass it via environment variables):
```toml
[profile.release]
debug = true  # Force full debug symbols generation even in release builds
```
Then compile using the standard release command:
```powershell
& 'C:\Users\Doome\.cargo\bin\cargo.exe' build -p yara-x-capi --release --target x86_64-pc-windows-msvc --features pulley
```
This will output an optimized DLL with a matching `.pdb` file inside `target/x86_64-pc-windows-msvc/release/`.
