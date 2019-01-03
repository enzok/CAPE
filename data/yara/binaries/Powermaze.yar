rule CrowdStrike_CSIT_18196_01 : powermaze rat stardust_chollima 
{
    meta:
        copyright = "(c) 2018 CrowdStrike Inc."
        description = "Detects STARDUST CHOLLIMA PowerMaze through Base64 encoded strings"
        reports = "CSIT-18196"
        version = "201812201216"
        last_modified = "2018-12-20"
        actor = "STARDUST CHOLLIMA"
        malware_family = "Powermaze"
        cape_type = "Powermaze"
    strings:
        $ = "'UABSAE8AQwBFAFMAUwBfAFIARQBRAFUARQBTAFQA'"//: 'PROCESS_REQUEST'
        $ = "'RABPAFcATgBMAE8AQQBEAF8AUwBUAE8AUAA='"//: 'DOWNLOAD_STOP'
        $ = "'QQBHAEUATgBUAF8AQwBPAE4ARgBJAEcA'"//: 'AGENT_CONFIG'
        $ = "'UABSAE8AQwBFAFMAUwBfAFQARQBSAE0ASQBOAEEAVABFAA=='"//: 'PROCESS_TERMINATE'
        $ = "'UgBFAEcAXwBOAEUAVwBfAFMAVABSAEkATgBHAA=='"//: 'REG_NEW_STRING'
        $ = "'RgBJAEwARQBfAFUATgBaAEkAUABfAFIARQBRAFUARQBTAFQA'"//: 'FILE_UNZIP_REQUEST'
        $ = "'UgBFAEcASQBTAFQAUgBZAF8AUgBFAFEAVQBFAFMAVAA='"//: 'REGISTRY_REQUEST'
        $ = "'UgBFAEcAXwBOAEUAVwBfAEIASQBOAEEAUgBZAA=='"//: 'REG_NEW_BINARY'
        $ = "'XAAlADIAMwAlAFIAUwAuAHQAbQBwAA=='"//: '\%23%RS.tmp'
        $ = "'RABPAFcATgBMAE8AQQBEAF8AUgBFAFEAVQBFAFMAVAA='"//: 'DOWNLOAD_REQUEST'
        $ = "'UgBFAEcAXwBOAEUAVwBfAEsARQBZAA=='"//: 'REG_NEW_KEY'
        $ = "'RgBJAEwARQBfAFIARQBRAFUARQBTAFQA'"//: 'FILE_REQUEST'
        $ = "'UgBFAEcAXwBEAEUATABFAFQARQA='"//: 'REG_DELETE'
        $ = "'UABSAE8AQwBFAFMAUwBfAEkATgBKAEUAQwBUAA=='"//: 'PROCESS_INJECT'
        $ = "'UwBDAFIARQBFAE4AXwBSAEUAUQBVAEUAUwBUAA=='" //: 'SCREEN_REQUEST'
        $ = "'SwBFAFkAQgBPAEEAUgBEAF8AUwBUAE8AUAA='"//: 'KEYBOARD_STOP'
        $ = "'QwBNAEQAXwBSAEUAUQBVAEUAUwBUAA=='"//: 'CMD_REQUEST'
        $ = "'XABEAGUAYwBvAG0AcAByAGUAcwBzAGUAZAA='"//: '\Decompressed'
        $ = "'UgBFAEcAXwBOAEUAVwBfAEQAVwBPAFIARAA='"//: 'REG_NEW_DWORD'
        $ = "'SwBFAFkAQgBPAEEAUgBEAF8AUgBFAFEAVQBFAFMAVAA='"//: 'KEYBOARD_REQUEST'
    condition:
        5 of them
}

rule CrowdStrike_CSIT_18196_02 : powershell stardust_chollima 
{
    meta:
        copyright = "(c) 2018 CrowdStrike Inc."
        description = "Detects STARDUST CHOLLIMA PowerShell obfuscator through characteristic variable naming"
        reports = "CSIT-18196"
        version = "201812201217"
        last_modified = "2018-12-20"
        actor = "STARDUST CHOLLIMA"
        cape_type = "Powermaze"
    strings:
        // ${global:dac8b255ec2a4362840e51143e4e57b2}
        $var_re = /\$\{global\:[a-f0-9]{32}\} = /
    condition:
        filesize < 500KB and
        $var_re
}

