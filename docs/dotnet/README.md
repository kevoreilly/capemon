# .NET JIT VTable Offset Extraction & Reconstruction Guide

This document details the internal structure of the Common Language Runtime (CLR) JIT-EE (Execution Engine) interface, explains why method-name resolution during compilation requires dynamic vtable slot tracking, and provides an automated tool to extract these slots across any target .NET runtime.

---

## Technical Background

During .NET compilation, the JIT compiler (`clrjit.dll` or `mscorjit.dll`) implements the `ICorJitCompiler::compileMethod` entry point. To log which managed method is being compiled (crucial for config extraction and dynamic malware unpacking), the sandbox hooks `compileMethod`.

Inside this hook, the runtime passes a pointer to the Execution Engine (`ICorJitInfo* compHnd`). Because `ICorJitInfo` is an unmanaged C++ interface, method calls (like retrieving the method name) must be dispatched via its **Virtual Function Table (VTable)**.

### The Problem: VTable Instability
Microsoft does not guarantee ABI stability for the internal JIT-EE interface between runtime versions. On almost every major release of .NET Core (and occasionally during servicing releases), virtual methods are added, removed, or reordered inside `ICorStaticInfo` and `ICorMethodInfo`.
* Calling an incorrect vtable slot will invoke the wrong function signature, corrupting the CPU registers or the call stack, resulting in immediate process crash or FailFast termination.
* To solve this, `capemon` uses version-specific slot gating. Unknown runtimes fail-safe by skipping name translation entirely, avoiding crashes.

---

# .NET ICorJitInfo/CEEJitInfo VTable Slots

This folder contains documentation and tooling for analyzing the **`ICorJitInfo`** and **`CEEJitInfo`** virtual function tables (vtables) across various .NET versions.

In the .NET runtime, RyuJIT (the JIT compiler) communicates with the Execution Engine (EE) via this virtual interface. Because they reside in separate binaries (`clrjit.dll`/`coreclr.dll`), the vtable method slots are strictly versioned. When creating runtime hooks or modifying compiler behaviors, knowing the exact virtual slot index of JIT methods like `getMethodNameFromMetadata` is critical.

---

## VTable Slot Index Reference

The following table lists the calculated vtable slot indices for the primary metadata method used by RyuJIT across 15 different .NET runtime versions.

* **CoreCLR 2.1+ / 5+**: Prioritizes `getMethodNameFromMetadata` (RyuJIT's modern metadata function).
* **CoreCLR <= 2.0 & Framework**: Prioritizes `getMethodName` (the older metadata function name used prior to 2.1).

| Runtime Type | Runtime Version | Method Name | Calculated Slot Index | Target Binary |
| :--- | :--- | :--- | :---: | :--- |
| **CoreCLR** | 1.1.13 | `getMethodName` | **105** | `coreclr.dll` |
| **CoreCLR** | 2.0.9 | `getMethodName` | **106** | `coreclr.dll` |
| **CoreCLR** | 2.1.30 | `getMethodNameFromMetadata` | **114** | `coreclr.dll` |
| **CoreCLR** | 2.2.8 | `getMethodNameFromMetadata` | **114** | `coreclr.dll` |
| **CoreCLR** | 3.0.3 | `getMethodNameFromMetadata` | **118** | `coreclr.dll` |
| **CoreCLR** | 3.1.32 | `getMethodNameFromMetadata` | **118** | `coreclr.dll` |
| **CoreCLR** | 3.1.426 | `getMethodNameFromMetadata` | **118** | `coreclr.dll` |
| **Framework** | 4.8 | `getMethodName` | **113** | `clr.dll` |
| **CoreCLR** | 5.0.408 | `getMethodNameFromMetadata` | **113** | `coreclr.dll` |
| **CoreCLR** | 6.0.36 | `getMethodNameFromMetadata` | **115** | `coreclr.dll` |
| **CoreCLR** | 7.0.410 | `getMethodNameFromMetadata` | **117** | `coreclr.dll` |
| **CoreCLR** | 8.0.24 | `getMethodNameFromMetadata` | **115** | `coreclr.dll` |
| **CoreCLR** | 8.0.30 | `getMethodNameFromMetadata` | **115** | `coreclr.dll` |
| **CoreCLR** | 9.0.19 | `getMethodNameFromMetadata` | **120** | `coreclr.dll` |
| **CoreCLR** | 10.0.11 | `getMethodNameFromMetadata` | **122** | `coreclr.dll` |

---

## Tooling: `Get-DotNetVTableSlots.ps1`

We provide a PowerShell automation script `Get-DotNetVTableSlots.ps1` inside this folder which extracts these slot numbers autonomously.

### How it Works
The script loads the targeted `coreclr.dll` or `clr.dll` dump in **CDB (Microsoft Console Debugger)**, automatically downloading the appropriate public PDB symbols from the Microsoft Symbol Server:
1. It runs `x coreclr!CEEJitInfo::*vftable*` (or `clr!CEEJitInfo::*vftable*`) to find all candidate virtual table addresses of the `CEEJitInfo` class (including nested inheritance tables).
2. It dumps the vtable slots using the addresses via `dps <addr> L250`.
3. It maps each entry's virtual method name.
4. It mathematically calculates the index of the method in the vtable:
   $$\text{Slot Index} = \frac{\text{Method Address} - \text{VTable Base Address}}{\text{Pointer Size (8 for x64, 4 for x86)}}$$

---

## How to Source Runtime Binaries

To extract offsets or verify a new servicing build, you must obtain the corresponding runtime engine DLL (`coreclr.dll`, `clr.dll`, or `mscorwks.dll`) and download its debugging symbols (`.pdb`).

### 1. Sourcing .NET Core / 5+ Binaries
Standard NuGet packages contain pristine, architecture-isolated copies of the runtime:
1. Construct the download link:
   `https://www.nuget.org/api/v2/package/Microsoft.NETCore.App.Runtime.win-x64/<VERSION>`
   *(e.g., https://www.nuget.org/api/v2/package/Microsoft.NETCore.App.Runtime.win-x64/8.0.11)*
2. Download and rename the package extension from `.nupkg` to `.zip`.
3. Extract and navigate to `/runtimes/win-x64/native/coreclr.dll` and `clrjit.dll`.

### 2. Sourcing .NET Framework Binaries
To extract the binaries from official offline installer packages without full installation:
1. Download the offline installer executable (e.g., `ndp48-x86-x64-allos-enu.exe`).
2. Run extraction from the command line:
   ```cmd
   ndp48-x86-x64-allos-enu.exe /x:C:\ExtractedFramework
   ```
3. Open the `.cab` archives inside the extraction folder to locate `clr.dll` or `mscorwks.dll`.

---

### 3. Automated VTable Extraction Script
To scan all runtime binaries recursively and update the table:

1. Open a PowerShell console.
2. Allow PowerShell script execution in your process:
   ```powershell
   Set-ExecutionPolicy Bypass -Scope Process
   ```
3. Run the script:
   ```powershell
   .\Get-DotNetVTableSlots.ps1
   ```
