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
