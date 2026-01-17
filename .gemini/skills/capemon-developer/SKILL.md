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

### 2. Advanced Malware Analysis (CAPE)
Integration of specialized CAPE features for automated analysis:
- **Config & Payload Extraction:** Automated extraction of malware configurations and decrypted payloads from memory.
- **Unpacking:** Dynamic unpacking of packed executables.
- **AMSI Dumping:** Intercepting and dumping buffers passed to the Antimalware Scan Interface (AMSI).
- **YARA Integration:** In-memory YARA scanning for identifying known malware families and behaviors.
- **Instruction Tracing:** Low-level tracing of execution paths for detailed analysis.

### 3. PE Analysis & Reconstruction
Utilizes components from Scylla and other libraries for:
- **PE Dumping:** Dumping running processes or specific modules from memory.
- **Import Reconstruction:** Repairing Import Address Tables (IAT) to create functional dumped executables.
- **WOW64 Support:** Comprehensive monitoring of 32-bit processes running on 64-bit Windows.

### 4. Data Logging & Serialization
- **BSON Logging:** Efficient serialization of captured events into BSON format for consumption by the CAPE backend.
- **Pipe Communication:** Secure communication channel back to the CAPE analyzer.

## Technical Foundations
- **Platform:** Windows (x86 and x64).
- **Hooking Method:** Inline hooking of Win32 and Native APIs (NTAPI).
- **Dependencies:** 
    - `distorm` for instruction decoding.
    - `libyara` for pattern matching.
    - `Scylla` for PE reconstruction.
    - `bson` for data serialization.
