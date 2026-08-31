# Extract-DotNetJitLayout.ps1
# Automates the extraction of ICorJitInfo/CEEJitInfo vtable slots and method signatures across multiple .NET versions.
# Set-ExecutionPolicy Bypass -Scope Process
param (
    [string]$RootFolder = "",
    [string]$SymbolCache = "C:\Symbols",
    [string]$CdbPath = ""
)

# Resolve default RootFolder based on script location
if ([string]::IsNullOrEmpty($RootFolder)) {
    if ($PSScriptRoot) {
        $RootFolder = (Resolve-Path "$PSScriptRoot\..\..\..").Path
    } else {
        $RootFolder = "."
    }
}

# 1. Attempt to auto-locate cdb.exe if not specified
if ([string]::IsNullOrEmpty($CdbPath)) {
    $searchPaths = @(
        "C:\Program Files (x86)\Windows Kits\10\Debuggers\x64\cdb.exe",
        "C:\Program Files (x86)\Windows Kits\10\Debuggers\x86\cdb.exe",
        "C:\Program Files\Windows Kits\10\Debuggers\x64\cdb.exe",
        "C:\Program Files\Windows Kits\10\Debuggers\x86\cdb.exe",
        "$env:LOCALAPPDATA\Microsoft\WindowsApps\cdb.exe"
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

Write-Host "Using CDB: $CdbPath" -ForegroundColor Cyan
Write-Host "Scanning Root Folder: $RootFolder" -ForegroundColor Cyan
Write-Host "Symbol Cache: $SymbolCache" -ForegroundColor Cyan
Write-Host "--------------------------------------------------" -ForegroundColor Gray

# 2. Find all clr.dll and coreclr.dll binaries
$targets = Get-ChildItem -Path $RootFolder -Recurse -Include "clr.dll", "coreclr.dll"

if ($targets.Count -eq 0) {
    Write-Warning "No 'clr.dll' or 'coreclr.dll' files found in the specified path structure."
    return
}

# Create a clean results array
$results = @()

foreach ($target in $targets) {
    # Get the parent directory name as the version representation
    $versionDir = Split-Path (Split-Path $target.FullName -Parent) -Leaf
    $fileName = $target.Name

    Write-Host "Processing $fileName ($versionDir)..." -ForegroundColor Yellow

    # Determine module name and default target method based on runtime type
    $moduleName = if ($fileName -eq "coreclr.dll") { "coreclr" } else { "clr" }
    $targetMethod = if ($fileName -eq "coreclr.dll") { "getMethodNameFromMetadata" } else { "getMethodName" }

    # Step 1: Find all candidate vtable addresses
    $vftableQuery = "x $moduleName!CEEJitInfo::*vftable*"
    $symPath = "srv*$SymbolCache*https://msdl.microsoft.com/download/symbols"
    $arguments = @("-z", "`"$($target.FullName)`"", "-y", "`"$symPath`"", "-c", "`"$vftableQuery; q`"")

    # Invoke CDB and capture the output
    $pinfo = New-Object System.Diagnostics.ProcessStartInfo
    $pinfo.FileName = $CdbPath
    $pinfo.Arguments = $arguments -join " "
    $pinfo.RedirectStandardOutput = $true
    $pinfo.UseShellExecute = $false
    $pinfo.CreateNoWindow = $true

    $process = [System.Diagnostics.Process]::Start($pinfo)
    $output = $process.StandardOutput.ReadToEnd()
    $process.WaitForExit()

    # Parse all candidate vtable addresses
    $vtableAddresses = @()
    $lines = $output -split "`r?`n"
    foreach ($line in $lines) {
        if ($line -match '^([0-9a-fA-F`]+)\s+\S+!CEEJitInfo::`?vftable') {
            $addr = $Matches[1] -replace '`', ''
            if ($vtableAddresses -notcontains $addr) {
                $vtableAddresses += $addr
            }
        }
    }

    $slotIndex = "Not Found (PDB mismatch or different method index)"

    # Try each candidate vtable address
    foreach ($vtableAddressHex in $vtableAddresses) {
        # Step 2: Dump the vtable entries (limit to 250 entries to be safe)
        $dpsQuery = "dps $vtableAddressHex L250"
        $arguments = @("-z", "`"$($target.FullName)`"", "-y", "`"$symPath`"", "-c", "`"$dpsQuery; q`"")

        $pinfo.Arguments = $arguments -join " "
        $process = [System.Diagnostics.Process]::Start($pinfo)
        $dpsOutput = $process.StandardOutput.ReadToEnd()
        $process.WaitForExit()

        # Parse dps output to find the index mathematically
        $baseDecimal = [Convert]::ToInt64($vtableAddressHex, 16)
        $pointerSize = if ($vtableAddressHex.Length -le 8) { 4 } else { 8 }

        $dpsLines = $dpsOutput -split "`r?`n"
        $found = $false
        
        # Pass 1: Look for the primary target method
        foreach ($line in $dpsLines) {
            if ($line -match '^\s*([0-9a-fA-F`]+)\s+([0-9a-fA-F`]+)\s+(.*)') {
                $entryAddressHex = $Matches[1] -replace '`', ''
                $symbolName = $Matches[3]
                
                if ($symbolName -like "*::$targetMethod") {
                    $entryDecimal = [Convert]::ToInt64($entryAddressHex, 16)
                    $slotIndex = ($entryDecimal - $baseDecimal) / $pointerSize
                    $found = $true
                    break
                }
            }
        }
        
        # Pass 2: Fallback to getMethodName if primary not found (for older CoreCLR versions)
        if (-not $found -and $fileName -eq "coreclr.dll") {
            foreach ($line in $dpsLines) {
                if ($line -match '^\s*([0-9a-fA-F`]+)\s+([0-9a-fA-F`]+)\s+(.*)') {
                    $entryAddressHex = $Matches[1] -replace '`', ''
                    $symbolName = $Matches[3]
                    
                    if ($symbolName -like "*::getMethodName") {
                        $entryDecimal = [Convert]::ToInt64($entryAddressHex, 16)
                        $slotIndex = ($entryDecimal - $baseDecimal) / $pointerSize
                        $targetMethod = "getMethodName"
                        $found = $true
                        break
                    }
                }
            }
        }
        if ($found) {
            break
        }
    }

    # Step 3: Extract Method Signature (Arguments & Types)
    $sigQuery = "x $moduleName!*CEEInfo::*${targetMethod}*"
    $sigArguments = @("-z", "`"$($target.FullName)`"", "-y", "`"$symPath`"", "-c", "`"$sigQuery; q`"")
    
    $pinfo.Arguments = $sigArguments -join " "
    $process = [System.Diagnostics.Process]::Start($pinfo)
    $sigOutput = $process.StandardOutput.ReadToEnd()
    $process.WaitForExit()
    
    $methodSig = "Unknown"
    $sigLines = $sigOutput -split "`r?`n"
    foreach ($line in $sigLines) {
        if ($line -match "(.*::$targetMethod.*)") {
            if ($line -match "\(([^)]*)\)") {
                $methodSig = "($($Matches[1]))"
                break
            }
        }
    }

    # Append to results
    $results += [PSCustomObject]@{
        "Runtime"   = if ($fileName -eq "coreclr.dll") { "CoreCLR" } else { "Framework" }
        "Version"   = $versionDir
        "Method"    = $targetMethod
        "Slot"      = $slotIndex
        "Signature" = $methodSig
        "Path"      = $target.FullName
    }
}

# 3. Output summary
Write-Host "`nAnalysis Complete!`n" -ForegroundColor Green
$results | Format-Table -AutoSize
