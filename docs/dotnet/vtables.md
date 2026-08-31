# .NET JIT VTable Offset Extraction & Reconstruction Guide

This document details the internal structure of the Common Language Runtime (CLR) JIT-EE (Execution Engine) interface, explains why method-name resolution during compilation requires dynamic vtable slot tracking, lists verified slots and signatures across various .NET versions, and provides an automated tool to extract these slots and signatures from any target .NET runtime.

---

## Technical Background

During .NET compilation, the JIT compiler (`clrjit.dll` or `mscorjit.dll`) implements the `ICorJitCompiler::compileMethod` entry point. To log which managed method is being compiled (crucial for config extraction and dynamic malware unpacking), the sandbox hooks `compileMethod`.

Inside this hook, the runtime passes a pointer to the Execution Engine (`ICorJitInfo* compHnd`). Because `ICorJitInfo` is an unmanaged C++ interface, method calls (like retrieving the method name) must be dispatched via its **Virtual Function Table (VTable)**.

### The Problem: VTable Instability & ABI Evolution
Microsoft does not guarantee ABI stability for the internal JIT-EE interface between runtime versions. On almost every major release of .NET Core (and occasionally during servicing releases), virtual methods are added, removed, or reordered inside `ICorStaticInfo` and `ICorMethodInfo`.
* Calling an incorrect vtable slot will invoke the wrong function signature, corrupting the CPU registers or the call stack, resulting in immediate process crash or FailFast termination.
* **Calling Convention Constraints:** On 32-bit (x86) platforms, virtual functions use the `__thiscall` calling convention, where the `this` pointer is passed in the `ECX` register, and other parameters are passed on the stack. Because standard C does not support the `__thiscall` keyword on function pointers under pure C compilation (`/TC`), `capemon` emulates this by declaring the pointers as `__fastcall` with a `dummy` second parameter. The first parameter (`_this`) is mapped to `ECX`, the second (`dummy`) is mapped to `EDX` (and set to `NULL`), and the remaining parameters are successfully pushed onto the stack.

---

## Verified Method Signatures (ABI Shapes)

Through symbol analysis and JIT-EE design research, the retrieval methods fall into four distinct binary signatures depending on the .NET version:

### 1. **Framework V2 (ABI V2)**
*   **Method Name:** `getMethodName`
*   **Availability:** .NET Framework 2.0-4.8.1, CoreCLR 1.x / 2.0
*   **Signature:**
    ```cpp
    const char* getMethodName(CORINFO_METHOD_HANDLE ftn, const char** moduleName);
    ```
*   **Parameters (2 args, excluding `this`):** Method handle, and a double-pointer output where the module/class name pointer is written.

### 2. **Core V3 (ABI V3)**
*   **Method Name:** `getMethodNameFromMetadata`
*   **Availability:** .NET Core 2.1 - 2.2
*   **Signature:**
    ```cpp
    const char* getMethodNameFromMetadata(CORINFO_METHOD_HANDLE ftn, const char** className, const char** namespaceName);
    ```
*   **Parameters (3 args, excluding `this`):** Method handle, class name output pointer, and namespace name output pointer.

### 3. **Core V4 (ABI V4)**
*   **Method Name:** `getMethodNameFromMetadata`
*   **Availability:** .NET Core 3.0 - 3.1, .NET 5.0 - 8.0, .NET 10.0
*   **Signature:**
    ```cpp
    const char* getMethodNameFromMetadata(CORINFO_METHOD_HANDLE ftn, const char** className, const char** namespaceName, const char** enclosingClassName);
    ```
*   **Parameters (4 args, excluding `this`):** Adds a 4th argument, `enclosingClassName`, for nested types.

### 4. **Core V5 (ABI V5)**
*   **Method Name:** `getMethodNameFromMetadata`
*   **Availability:** .NET 9.0
*   **Signature:**
    ```cpp
    const char* getMethodNameFromMetadata(CORINFO_METHOD_HANDLE ftn, const char** className, const char** namespaceName, const char** enclosingClassName, size_t maxEnclosingClassNames);
    ```
*   **Parameters (5 args, excluding `this`):** Adds a 5th argument, `maxEnclosingClassNames`, representing the recursion limit to prevent stack overflows while traversing highly nested classes.

---

## Consolidated Offset Reference

This table contains the exact, 0-based vtable slot indexes and method signatures verified empirically against public symbols and live shipping binaries.

| Runtime Family | Runtime Version | Runtime DLL | Method Name | Slot Index (0-based) | Arguments (excluding `this`) | ABI Version |
| :--- | :--- | :--- | :--- | :---: | :--- | :---: |
| **.NET Framework** | **4.0 - 4.8.1** | `clr.dll` | `getMethodName` | **113** | `(CORINFO_METHOD_HANDLE ftn, const char** moduleName)` | **ABI V2** |
| **.NET Core** | **1.1** | `coreclr.dll` | `getMethodName` | **105** | `(CORINFO_METHOD_HANDLE ftn, const char** moduleName)` | **ABI V2** |
| **.NET Core** | **2.0** | `coreclr.dll` | `getMethodName` | **106** | `(CORINFO_METHOD_HANDLE ftn, const char** moduleName)` | **ABI V2** |
| **.NET Core** | **2.1 - 2.2** | `coreclr.dll` | `getMethodNameFromMetadata` | **114** | `(CORINFO_METHOD_HANDLE, const char**, const char**)` | **ABI V3** |
| **.NET Core** | **3.0 - 3.1** | `coreclr.dll` | `getMethodNameFromMetadata` | **118** | `(CORINFO_METHOD_HANDLE, const char**, const char**, const char**)` | **ABI V4** |
| **.NET** | **5.0** | `coreclr.dll` | `getMethodNameFromMetadata` | **113** | `(CORINFO_METHOD_HANDLE, const char**, const char**, const char**)` | **ABI V4** |
| **.NET** | **6.0** | `coreclr.dll` | `getMethodNameFromMetadata` | **115** | `(CORINFO_METHOD_HANDLE, const char**, const char**, const char**)` | **ABI V4** |
| **.NET** | **7.0** | `coreclr.dll` | `getMethodNameFromMetadata` | **117** | `(CORINFO_METHOD_HANDLE, const char**, const char**, const char**)` | **ABI V4** |
| **.NET** | **8.0** | `coreclr.dll` | `getMethodNameFromMetadata` | **115** | `(CORINFO_METHOD_HANDLE, const char**, const char**, const char**)` | **ABI V4** |
| **.NET** | **9.0** | `coreclr.dll` | `getMethodNameFromMetadata` | **120** | `(CORINFO_METHOD_HANDLE, const char**, const char**, const char**, size_t)` | **ABI V5** |
| **.NET** | **10.0** | `coreclr.dll` | `getMethodNameFromMetadata` | **122** | `(CORINFO_METHOD_HANDLE, const char**, const char**, const char**, size_t)` | **ABI V5** |

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

## Automated VTable & Signature Extraction Script

The PowerShell script `Extract-DotNetJitLayout.ps1` (located in this directory) recursively scans any directory structure specified by the user, loads found runtimes, fetches public symbols from Microsoft's public symbol server, and displays:
*   The exact 0-based virtual function slot.
*   The exact method name and parameter types.
*   The fully resolved runtime versions.

To run the check against any directory containing your downloaded DLLs, pass the directory path to the `-RootFolder` parameter:

```powershell
Set-ExecutionPolicy Bypass -Scope Process
.\Extract-DotNetJitLayout.ps1 -RootFolder "C:\Path\To\Your\Dotnet\Libs"
```
