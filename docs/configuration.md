# Capemon Configuration Reference

This document outlines the available configuration options for `capemon`, the monitoring component of CAPE Sandbox. These options control various aspects of the analysis, including hooking behavior, logging, anti-evasion techniques, and payload dumping.

They are typically defined in the analysis configuration file (e.g., `config.ini`) or passed dynamically by the sandbox agent.

## General Configuration

| Option | Value Type | Description |
| :--- | :--- | :--- |
| `pipe` | String | Name of the pipe used to communicate with the analyzer (Cuckoo/CAPE). |
| `logserver` | String | IP address or path for the log server. |
| `results` | Path | Directory where analysis results will be stored. |
| `analyzer` | Path | Directory where the analyzer is located (also sets the DLL path). |
| `pythonpath` | Path | Directory for Python (used for Python-based analysis tools). |
| `shutdown-mutex` | String | Name of the mutex that signals a shutdown/termination. |
| `first-process` | Boolean | (Internal) Flag indicating if this is the first process in the analysis tree. |
| `startup-time` | Integer | System startup time in milliseconds. |
| `debug` | Integer | Debug level: `1` = Report critical exceptions, `2` = Report all exceptions. |
| `lang` | Integer | Override the system language code (LCID). |
| `terminate-event` | String | Name of the event set by the analyzer to signal termination. |
| `terminate-processes` | Boolean | If `true`, terminate processes when `terminate-event` is signaled. |
| `monitor` | PID/String | Inject the monitor into a specific PID or `explorer` (for interactive mode). |

## Logging & Output

| Option | Value Type | Description |
| :--- | :--- | :--- |
| `full-logs` | Boolean | Disable log suppression (by default, logs before network/file activity are suppressed). |
| `force-flush` | Integer | `1` = Flush logs after any non-duplicate API, `2` = Force flush every log. |
| `log-exceptions` | Boolean | Enable logging of exceptions (via `RtlDispatchException`). |
| `log-vexcept` | Boolean | Enable logging of Vectored Exception Handlers. |
| `log-breakpoints` / `log-bps` | Boolean | Enable logging of breakpoints to the behavior log. |
| `trace-times` / `tt` | Boolean | Enable timing information in traces. |
| `buffer-max` | Integer | Maximum size for the log buffer. |
| `large-buffer-max` | Integer | Maximum size for large log buffers. |
| `no-logs` | Integer | Divert debugger logs (1 - divert to analysis log, 2 - throw away completely) |
| `disable-logging` | Boolean | Completely disable the analysis log. |

## Hooking Behavior

| Option | Value Type | Description |
| :--- | :--- | :--- |
| `hook-type` | String | Hooking method: `indirect`, `pushret`, `direct`, `safe`. Defaults to `indirect` (x64) or `hotpatch` (x86). |
| `hook-range` | Integer | Limit the number of applied hooks (useful for testing). |
| `hook-low` | Boolean | (x64) Allocate hook trampolines in low memory (<2GB). |
| `hook-restore` | Boolean | Attempt to restore hooks if modification is detected by the unhook thread. |
| `disable-hook-content` | Integer | `1` = Remove payload of non-critical hooks, `2` = Remove payload of all hooks. |
| `hook-protect` | Boolean | Enable write protection on hook pages. |
| `minhook` | Boolean | Enable only a minimal set of hooks. |
| `zerohook` | Boolean | Disable all hooks except those essential for process monitoring. |
| `native` | Boolean | Install only native (ntdll) hooks. |
| `syscall` | Boolean | Enable syscall hooks. |
| `hook-watch` | Boolean | Enable monitoring/watching of hooks integrity. |
| `coverage-modules` | List | Colon-separated list of DLLs to include in monitoring (exclude from 'dll range' filtering). |
| `exclude-apis` | List | Colon-separated list of APIs to exclude from hooking. |
| `exclude-dlls` | List | Colon-separated list of DLLs to exclude from hooking. |
| `unhook-apis` | List | Colon-separated list of already hooked APIs to unhook at runtime. |
| `unhook-on-terminate` | Boolean | If `true`, restore all hooked API original bytes to memory when the process terminates. |
| `api-rate-cap` | Integer | Limit the rate of API logging. |
| `api-cap` | Integer | Limit the total number of API logs allowed. |

## Anti-Evasion & Stealth

| Option | Value Type | Description |
| :--- | :--- | :--- |
| `no-stealth` | Boolean | Disable anti-anti-VM/sandbox tricks. |
| `force-sleepskip` | Boolean | `0` = Disable sleep skipping, `1` = Skip all sleeps. |
| `sleep-skip-seconds` | Integer | Threshold and delay (in seconds) to replace clamped/skipped sleeps and timeouts with (default: 10). |
| `serial` | Hex | Spoof the system volume serial number. |
| `sysvol_ctimelow` | Hex | Spoof the low part of the creation time of the system volume. |
| `sysvol_ctimehigh` | Hex | Spoof the high part of the creation time of the system volume. |
| `sys32_ctimelow` | Hex | Spoof the low part of the creation time of the System32 directory. |
| `sys32_ctimehigh` | Hex | Spoof the high part of the creation time of the System32 directory. |
| `fake-rdtsc` | Boolean | Enable fake RDTSC (Read Time-Stamp Counter) results. |
| `nop-rdtscp` | Boolean | NOP (No Operation) the RDTSCP instruction. |
| `cpu-count` | Integer | Spoof the number of CPU cores (default: 4). |
| `ntdll-protect` | Boolean | Enable write protection on `ntdll.dll` code (enabled by default). |
| `ntdll-unhook` | Boolean | Enable protection against `ntdll` unhooking (via `NtReadFile`). |
| `ntdll-remap` | Boolean | Enable `ntdll` remapping protection. |
| `protected-pids` | Boolean | Enable protection for critical PIDs (prevent termination/injection). |

## Dumping & Payloads

| Option | Value Type | Description |
| :--- | :--- | :--- |
| `dump-limit` | Integer | Limit the number of payload dumps (default: 10). |
| `dropped-limit` | Integer | Limit the number of dropped files logged (default: 100). |
| `procdump` | Integer | Enable process memory dumping on exit/timeout (1 - dump if changed from image (default), 2 - always dump). |
| `procmemdump` | Boolean | Enable *full* process memory dumping. |
| `import-reconstruction` | Boolean | Perform import reconstruction on process dumps. |
| `dump-on-api` | List | Dump the calling module when specific APIs (colon-separated) are called. |
| `dump-on-api-type` | Integer | Type of dump to perform for `dump-on-api`. |
| `dump-config-region` | Boolean | Dump memory regions suspected to contain C2 configuration. |
| `dump-crypto` | Boolean | Dump buffers from Crypto APIs. |
| `dump-keys` | Boolean | Dump keys from `CryptImportKey`. |
| `amsidump` | Boolean | Enable AMSI buffer dumping (Windows 10+). |
| `yarascan` | Boolean | Enable in-memory YARA scanning of process memory, including JIT-compiled native code and decrypted MSIL bytecode payloads. |
| `yara-timeout` | Integer | Timeout limit in milliseconds for in-memory YARA scanning (default: 60000). |
| `dumpsize` | Integer | Maximum size in bytes allowed for a single raw memory dump. |
| `jit-dumps` | Integer | Limit for .NET JIT cache and MSIL bytecode dumps. |
| `tlsdump` | Boolean | Enable dumping of TLS secrets. |
| `regdump` | Boolean | Enable dumping of Registry data. |
| `unpacker` | Integer | `1` = Passive unpacking (default), `2` = Active unpacking. |
| `injection` | Boolean | Enable capture of injected payloads between processes (enabled by default). |

## Debugging & Tracing (Advanced)

| Option | Value Type | Description |
| :--- | :--- | :--- |
| `debugger` | Boolean | Enable the internal debugger engine (implicitly set by bp/trace options, not used directly). |
| `bp0`...`bp3` | Addr/String | Set hardware breakpoint. Format: `0xAddress`, `Module:Export`, `zero` (clear), or `ep` (entrypoint). |
| `br0`, `br1` | Addr/String | Set "break-on-return" addresses. |
| `bp` | List | Colon-separated list of addresses for software breakpoints. |
| `sysbp` | List | Colon-separated list of addresses for syscall breakpoints. |
| `sysbpmode` | Integer | Mode for syscall breakpoints. |
| `softbpmode` | Integer | Execution mode behavior for software breakpoints. |
| `break-on-return` | List | Colon-separated list of APIs to break on return. |
| `break-on-jit` | Boolean | Break on .NET JIT compiled native code. |
| `idbg` | Boolean | Enable interactive remote debugger interface (CAPEsolo internal). |
| `trace-all` | Boolean | Enable full execution tracing. |
| `trace-into-api` | List | Colon-separated list of APIs to trace into. |
| `branch-trace` | Boolean | Enable branch tracing. |
| `depth` | Integer/All | Trace depth limit (or "all"). |
| `count` | Integer/All | Trace instruction count limit (or "all"). |
| `step-out` | Address | Set a step-out breakpoint at a specific address. |
| `stepmode` | Integer | Custom trace stepping behavior. |
| `loopskip` | Boolean | Enable loop skipping in instruction traces. |
| `base-on-api` | List | Set base address for breakpoints based on specific APIs. |
| `base-on-alloc` | Boolean | Base breakpoints on executable memory allocations. |
| `base-on-caller` | Boolean | Base breakpoints on new calling regions. |
| `file-offsets` | Boolean | Interpret breakpoints as file offsets instead of RVAs. |
| `loaderlock` | Boolean | Allow scans/dumps while the Loader Lock is held. |
| `loaderlock-settle` | Boolean | Yield in loader hooks while the Loader Lock is held. Timing fix for trojanized sideload DLLs (e.g. AxolotlLoader) whose DllMain bootstrap races a dispatch-table slot; opt-in per-sample. |
| `snaps` | Boolean | Enable Windows Loader Snaps output (LdrSnap). |

## Target Specific

| Option | Value Type | Description |
| :--- | :--- | :--- |
| `file-of-interest` | String | The specific file or URL being analyzed. |
| `referrer` | String | Fake referrer to use for URL analysis. |
| `single-process` | Boolean | Prevent monitoring of child processes. |
| `interactive` | Boolean | Enable interactive desktop mode. |
| `pdf` | Boolean | Enable specific hooks/behavior for Adobe Reader. |
| `standalone` | Boolean | Run in standalone mode (no Cuckoo pipe). |
