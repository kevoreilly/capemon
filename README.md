capemon: The monitor DLLs for CAPE: Config And Payload Extraction.

CAPE is an extension of Cuckoo specifically designed to extract payloads and configuration from malware. It is derived from spender-sandbox, thanks to Brad Spengler and the rest of the Cuckoo contributors.

Much of the functionality of CAPE is contained within the monitor DLLs. The different CAPE 'packages' are embodied within these DLLs, and this repository is organised in branches.

The 'standard' package is in the capemon branch.

The three 'behavioural' packages are contained within the following branches:

	Compression
	Extraction
	Injection

Additional malware-specific packages are within the following branches:

	Azzy
	EvilGrab
	PlugX

A package to dynamically unpack 'hacked' UPX binaries is in the 'UPX' branch.
