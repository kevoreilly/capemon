## capemon: The monitor DLLs for CAPE: Config And Payload Extraction (https://github.com/ctxis/CAPE).

Much of the functionality of CAPE is contained within the monitor DLLs; the CAPE debugger and the different CAPE 'packages' are implemented within the DLLs. This repository is organised in branches for each of the packages.

The 'standard' package is in the capemon branch.

The three 'behavioural' packages are contained within the following branches:

- Compression
- Extraction
- Injection

These are designed to dump malware payloads associated with the respective behaviours.

Additional malware-specific packages are within the following branches:

- Cerber
- EvilGrab
- PlugX
- Sedreco

These allow for the extraction of both payloads and malware configuration from the respective malware families.

There is also a UPX package to dynamically unpack 'hacked' UPX binaries.

CAPE is an extension of Cuckoo specifically designed to extract payloads and configuration from malware. It is derived from spender-sandbox, which is derived from Cuckoo Sandbox, so thanks to Brad Spengler, Claudio Guarnieri, and the countless other Cuckoo contributors without whom this work would not be possible.
