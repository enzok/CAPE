


This fork aims to continue the work of the heavily modified version of [Cuckoo Sandbox](http://www.cuckoosandbox.org) provided under the GPL by Optiv, Inc.

It offers a number of advantages over the upstream Cuckoo:
+ Fully-normalized file and registry names
+ 64-bit analysis
+ Handling of WoW64 filesystem redirection
+ Many additional API hooks
+ Service monitoring
+ Correlates API calls to malware call chains
+ Ability to follow APC injection and stealth explorer injection
+ Pretty-printed API flags
+ Per-analysis Tor support
+ Over 150 new signature modules (over 75 developed solely by Optiv)
+ Anti-anti-sandbox and anti-anti-VM techniques built-in
+ More stable hooking
+ Ability to restore removed hooks
+ Greatly improved behavioral analysis and signature module API
+ Ability to post comments about analyses
+ Deep hooks in IE's JavaScript and DOM engines usable for Exploit Kit identification
+ Automatic extraction and submission of interesting files from ZIPs, RARs, RFC 2822 emails (.eml), and Outlook .msg files
+ Direct submission of AV quarantine files (Forefront, McAfee, Trend Micro, Kaspersky, MalwareBytes, MSE/SCEP, and SEP12 formats currently supported)
+ Automatic malware classification by [Malheur](http://mlsec.org/malheur/)
+ Significant contributions from [Jeremy Hedges](https://github.com/killerinstinct/), [William Metcalf](https://github.com/wmetcalf), and Kevin Ross
+ Hundreds of other bugfixes

For more information on the initial set of changes, see:
https://www.optiv.com/blog/improving-reliability-of-sandbox-results

If you want to contribute to development, feel free to submit a pull request.




CAPE: Config And Payload Extraction

CAPE is an extension of Cuckoo specifically designed to extract payloads and configuration from malware.

CAPE can detect a number of malware techniques or behaviours, as well as specific malware families, from its initial run on a sample.

This detection then triggers a second run with a specific package, in order to extract the malware payload and possibly its configuration, for further analysis.

CAPE works by controlling malware via a bespoke debugger and API hooks. Detection to trigger a CAPE package can be based from on 'Cuckoo' (API) or Yara signatures. The debugger uses Yara signatures or API hooks to allow breakpoints to be set on individual instructions, memory regions or function calls. Once a region of interest is reached, it can be manipulated and dumped for processing and analysis, and possibly configuration parsing.

The techniques or behaviours that CAPE detects and has packages for include:
    - Process injection
        - Shellcode injection
        - DLL injection
        - Process Hollowing
    - Decompression of executable modules in memory
    - Extraction of executable modules or shellcode in memory

Packages for these behaviours will dump the payloads being injected, extracted or decompressed for further analysis. This is often the malware payload in unpacked form.

CAPE automatically creates a process dump for each process, or, in the case of a DLL, the DLL's module image in memory. This is useful for samples packed with simple packers, where often the module image dump is fully unpacked. Yara signatures may trigger on the process dumps, possibly resulting in submission with a specific package or configuration parsing.

CAPE also has a package which can dynamically unpack samples that use 'hacked' (modified) UPX, very popular with malware authors. These samples are run in CAPE's debugger until their OEP (original entry point), whereupon they are dumped, fixed and their imports are automatically reconstructed, ready for analysis.

Currently CAPE has specific packages dumping configuration and payloads for the following malware families:
    - PlugX
    - EvilGrab
    - Sedreco

Many other malware families have their payloads extracted by some of the behavioural packages, with their configuration in the clear in the resulting output. Configuration parsing may then be performed on this by virtue of Yara-based detection, and config parsing based on CAPE's primary config parsing framework, DC3-MWCP (Defense Cyber Crime Center - Malware Configuration Parser). Parsers may also be written using the RATDecoders framework from malwareconfig.com. Thanks to DC3 and Kevin Breen/TechAnarchy for these frameworks.

CAPE has config parsers for the following malware families, whose payloads are extracted by a behavioural package:
    - HttpBrowser
    - Enfal
    - ChChes
    - RedLeaf

The publicly available decoders from malwareconfig.com are also included in CAPE. This includes, among many others, Sakula, DarkComet and PoisonIvy.

CAPE also has Yara signatures to detect payloads that are extracted by a behavioural package. This list is growing, and includes:
    - WanaCry
    - Emotet
    - Cerber
    - Locky
    - Dridex
    - NetTraveler
    - ZeroT
    - Jaff
    - T5000
    
There are a number of other behavioural and malware family packages and parsers currently in the works, so watch this space.

Packages can be written based on API hooks, the CAPE debugger, or a combination of both.

The CAPE debugger allows four breakpoints to be set on each malware thread to detect on read, write or execute of a memory region, as well as single-step mode. This allows fine control over malware execution until it is possible to dump the memory regions of interest, containing code or configuration data. Breakpoints can be set dynamically by package code, API hooks or Yara signatures.

Processes, modules and memory regions can variously be dumped by CAPE through use of a simple API. These dumps can then be scanned and parsed for configuration information.

Executable modules are fixed on being dumped, and may also have their imports automatically reconstructed (based on Scylla).

The repository containing the code for the monitor DLLs which form the basis of these packages is a distinct one: https://github.com/ctxis/capemon. This repository is organised in branches for the various packages.

CAPE is derived from spender-sandbox, which is derived from Cuckoo Sandbox, so thanks to Brad Spengler, Claudio Guarnieri, and the countless other Cuckoo contributors without whom this work would not be possible.

Please contribute to this project by helping create new packages for further malware families, packers, techniques or configuration parsers. Alternatively contact us for further details of CAPE development.

