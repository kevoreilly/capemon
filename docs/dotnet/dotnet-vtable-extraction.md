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

## Consolidated Offset Reference

| Runtime Family | Runtime DLL | Method Name | Slot Index (0-based) | Arguments | Notes / Source Verification |
| --- | --- | --- | --- | --- | --- |
| **.NET Framework 2.0 - 3.5** | `mscorwks.dll` | `getMethodName` | **0** | 2 args | First method of `ICorMethodInfo` |
| **.NET Framework 4.0 - 4.8.1** | `clr.dll` | `getMethodName` | **0** | 2 args | Stable across all Windows servicing builds |
| **.NET Core 3.1** | `coreclr.dll` | `getMethodNameFromMetadata` | **141** | 4 args | `release/3.1` generated header |
| **.NET 5.0** | `coreclr.dll` | `getMethodNameFromMetadata` | **143** | 4 args | `release/5.0` generated header |
| **.NET 6.0** | `coreclr.dll` | `getMethodNameFromMetadata` | **143** | 5 args | `release/6.0` (introduces `maxEnclosingClassNames`) |
| **.NET 7.0** | `coreclr.dll` | `getMethodNameFromMetadata` | **143** | 5 args | `release/7.0` generated header |
| **.NET 8.0** | `coreclr.dll` | `getMethodNameFromMetadata` | **120** | 5 args | `release/8.0` ThunkInput ordinal 121 |
| **.NET 9.0** | `coreclr.dll` | `getMethodNameFromMetadata` | **120** | 5 args | `release/9.0` ThunkInput ordinal 121 |

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

## Automated VTable Extraction Script

Below is a PowerShell automation script that recursively searches a directory, loads each runtime library, automatically downloads the corresponding debugging symbols from Microsoft's public symbol server, and extracts the exact 0-based vtable slot index.

Save this script as `Get-DotNetVTableSlots.ps1` and run it:

```powershell
param (
    [string]$RootFolder = ".",
    [string]$SymbolCache = "C:\Symbols",
    [string]$CdbPath = ""
)

# Locate cdb.exe automatically
if ([string]::IsNullOrEmpty($CdbPath)) {
    $searchPaths = @(
        "C:\Program Files (x86)\Windows Kits\10\Debuggers\x64\cdb.exe",
        "C:\Program Files (x86)\Windows Kits\10\Debuggers\x86\cdb.exe",
        "C:\Program Files\Windows Kits\10\Debuggers\x64\cdb.exe",
        "C:\Program Files\Windows Kits\10\Debuggers\x86\cdb.exe"
    )
    foreach ($path in $searchPaths) {
        if (Test-Path $path) {
            $CdbPath = $path
            break
        }
    }
}

if (-not (Test-Path $CdbPath)) {
    Write-Error "Could not locate cdb.exe. Please install Windows Debugging Tools or specify -CdbPath."
    return
}

$targets = Get-ChildItem -Path $RootFolder -Recurse -Include "clr.dll", "coreclr.dll", "mscorwks.dll"
if ($targets.Count -eq 0) {
    Write-Warning "No target binaries found in the folder structure."
    return
}

$results = @()
foreach ($target in $targets) {
    $versionDir = Split-Path (Split-Path $target.FullName -Parent) -Leaf
    $fileName = $target.Name
    
    $symbolQuery = ""
    $targetMethod = ""
    if ($fileName -eq "coreclr.dll") {
        $symbolQuery = "dt coreclr!CEEJitInfo -v"
        $targetMethod = "getMethodNameFromMetadata"
    } elseif ($fileName -eq "clr.dll") {
        $symbolQuery = "dt clr!CEEJitInfo -v"
        $targetMethod = "getMethodName"
    } else {
        $symbolQuery = "dt mscorwks!CEEJitInfo -v"
        $targetMethod = "getMethodName"
    }

    $symPath = "srv*$SymbolCache*https://msdl.microsoft.com/download/symbols"
    $arguments = @("-z", "`"$($target.FullName)`"", "-y", "`"$symPath`"", "-c", "`"$symbolQuery; q`"")

    $pinfo = New-Object System.Diagnostics.ProcessStartInfo -Property @{
        FileName = $CdbPath
        Arguments = $arguments -join " "
        RedirectStandardOutput = $true
        UseShellExecute = $false
        CreateNoWindow = $true
    }
    
    $process = [System.Diagnostics.Process]::Start($pinfo)
    $output = $process.StandardOutput.ReadToEnd()
    $process.WaitForExit()

    $slotIndex = "Not Found (PDB mismatch or different method index)"
    $lines = $output -split "`r?`n"
    foreach ($line in $lines) {
        if ($line -match "\s+\[(\d+)\]\s+.*::$targetMethod") {
            $slotIndex = $Matches[1]
            break
        }
    }

    $results += [PSCustomObject]@{
        "Runtime" = if ($fileName -eq "coreclr.dll") { "CoreCLR" } else { "Framework" }
        "Version" = $versionDir
        "Method"  = $targetMethod
        "Slot"    = $slotIndex
        "Path"    = $target.FullName
    }
}

$results | Format-Table -AutoSize
```
