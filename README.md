## capemon: The monitor DLL for CAPE: Config And Payload Extraction (https://github.com/kevoreilly/CAPEv2).

Much of the functionality of CAPE is contained within the monitor; the CAPE debugger, extracted payloads, process dumps and import reconstruction are implemented within capemon. CAPE's loader is also part of this project.

capemon is derived from cuckoomon-modified from spender-sandbox (https://github.com/spender-sandbox/cuckoomon-modified) from which it inherits the API hooking engine. It also includes a PE dumping engine and import reconstruction derived from Scylla (https://github.com/NtQuery/Scylla), WOW64Ext Library from ReWolf (http://blog.rewolf.pl/) and W64oWoW64 fom George Nicolaou. 
