/*
    This Yara ruleset is under the GNU-GPLv2 license (http://www.gnu.org/licenses/gpl-2.0.html) and open to any user or organization, as long as you use it under this license.
*/

rule AdGholas_mem
{

    meta:
        malfamily = "AdGholas"
        ref = "https://www.proofpoint.com/us/threat-insight/post/massive-adgholas-malvertising-campaigns-use-steganography-and-file-whitelisting-to-hide-in-plain-sight"

    strings:
        $a1 = "(3e8)!=" ascii wide
        $a2 = /href=\x22\.\x22\+[a-z]+\,mimeType\}/ ascii wide
        $a3 = /\+[a-z]+\([\x22\x27]divx[^\x22\x27]+torrent[^\x22\x27]*[\x22\x27]\.split/ ascii wide
        $a4 = "chls" nocase ascii wide
        $a5 = "saz" nocase ascii wide
        $a6 = "flac" nocase ascii wide
        $a7 = "pcap" nocase ascii wide

    condition:
        all of ($a*)
}

rule AdGholas_mem_MIME 
{

    meta:
        malfamily = "AdGholas"
        ref = "https://www.proofpoint.com/us/threat-insight/post/massive-adgholas-malvertising-campaigns-use-steganography-and-file-whitelisting-to-hide-in-plain-sight"

    strings:
        $b1=".300000000" ascii nocase wide fullword
        $b2=".saz" ascii nocase wide fullword
        $b3=".py" ascii nocase wide fullword
        $b4=".pcap" ascii nocase wide fullword
        $b5=".chls" ascii nocase wide fullword

    condition:
        all of ($b*)
}

//expensive
rule AdGholas_mem_antisec : memory
{
 
    meta:
        malfamily = "AdGholas"
        ref = "https://www.proofpoint.com/us/threat-insight/post/massive-adgholas-malvertising-campaigns-use-steganography-and-file-whitelisting-to-hide-in-plain-sight"

    strings:
        $vid1 = "res://c:\\windows\\system32\\atibtmon.exe" nocase ascii wide
        $vid2 = "res://c:\\windows\\system32\\aticfx32.dll" nocase ascii wide
        $vid3 = "res://c:\\windows\\system32\\drivers\\ati2mtag.sys" nocase ascii wide
        $vid4 = "res://c:\\windows\\system32\\drivers\\atihdmi.sys" nocase ascii wide
        $vid5 = "res://c:\\windows\\system32\\drivers\\atikmdag.sys" nocase ascii wide
        $vid6 = "res://c:\\windows\\system32\\drivers\\igdkmd32.sys" nocase ascii wide
        $vid7 = "res://c:\\windows\\system32\\drivers\\igdkmd64.sys" nocase ascii wide
        $vid8 = "res://c:\\windows\\system32\\drivers\\igdpmd32.sys" nocase ascii wide
        $vid9 = "res://c:\\windows\\system32\\drivers\\igdpmd64.sys" nocase ascii wide
        $vid10 = "res://c:\\windows\\system32\\drivers\\mfeavfk.sys" nocase ascii wide
        $vid11 = "res://c:\\windows\\system32\\drivers\\mfehidk.sys" nocase ascii wide
        $vid12 = "res://c:\\windows\\system32\\drivers\\mfenlfk.sys" nocase ascii wide
        $vid13 = "res://c:\\windows\\system32\\drivers\\nvhda32v.sys" nocase ascii wide
        $vid14 = "res://c:\\windows\\system32\\drivers\\nvhda64v.sys" nocase ascii wide
        $vid15 = "res://c:\\windows\\system32\\drivers\\nvlddmkm.sys" nocase ascii wide
        $vid16 = "res://c:\\windows\\system32\\drivers\\pci.sys" nocase ascii wide
        $vid17 = "res://c:\\windows\\system32\\igd10umd32.dll" nocase ascii wide
        $vid18 = "res://c:\\windows\\system32\\igd10umd64.dll" nocase ascii wide
        $vid19 = "res://c:\\windows\\system32\\igdumd32.dll" nocase ascii wide
        $vid20 = "res://c:\\windows\\system32\\igdumd64.dll" nocase ascii wide
        $vid21 = "res://c:\\windows\\system32\\igdumdim32.dll" nocase ascii wide
        $vid22 = "res://c:\\windows\\system32\\igdumdim64.dll" nocase ascii wide
        $vid23 = "res://c:\\windows\\system32\\igdusc32.dll" nocase ascii wide
        $vid24 = "res://c:\\windows\\system32\\igdusc64.dll" nocase ascii wide
        $vid25 = "res://c:\\windows\\system32\\nvcpl.dll" nocase ascii wide
        $vid26 = "res://c:\\windows\\system32\\opencl.dll" nocase ascii wide
        /* If the next variable fails see https://github.com/Yara-Rules/rules/issues/176.
        You will need to modify yara source code and recompile.
        $antisec = /res:\/\/(c:\\((program files|programme|archivos de programa|programmes|programmi|arquivos de programas|program|programmer|programfiler|programas|fisiere program)( (x86)\\((p(rox(y labs\\proxycap\\pcapui|ifier\\proxifier)|arallels\\parallels tools\\prl_cc)|e(met (5.[012]|4.[01])\\emet_gui|ffetech http sniffer\\ehsniffer)|malwarebytes anti-(exploit\\mbae|malware\\mbam)|oracle\\virtualbox guest additions\\vboxtray|debugging tools for windows (x86)\\windbg|(wireshark\\wiresha|york\\yo)rk|ufasoft\\sockschain\\sockschain|vmware\\vmware tools\\vmtoolsd|nirsoft\\smartsniff\\smsniff|charles\\charles).exe|i(n(vincea\\((browser protection\\invbrowser|enterprise\\invprotect).exe|threat analyzer\\fips\\nss\\lib\\ssl3.dll)|ternet explorer\\iexplore.exe)|einspector\\(httpanalyzerfullv(6\\hookwinsockv6|7\\hookwinsockv7)|iewebdeveloperv2\\iewebdeveloperv2).dll)|geo(edge\\geo(vpn\\bin\\geovpn|proxy\\geoproxy).exe|surf by biscience toolbar\\tbhelper.dll)|s(oftperfect network protocol analyzer\\snpa.exe|andboxie\\sbiedll.dll)|(adclarity toolbar\\tbhelper|httpwatch\\httpwatch).dll|fiddler(coreapi\\fiddlercore.dll|2?\\fiddler.exe))|\\((p(rox(y labs\\proxycap\\pcapui|ifier\\proxifier)|arallels\\parallels tools\\prl_cc)|e(met (5.[012]|4.[01])\\emet_gui|ffetech http sniffer\\ehsniffer)|malwarebytes anti-(exploit\\mbae|malware\\mbam)|oracle\\virtualbox guest additions\\vboxtray|debugging tools for windows (x86)\\windbg|(wireshark\\wiresha|york\\yo)rk|ufasoft\\sockschain\\sockschain|vmware\\vmware tools\\vmtoolsd|nirsoft\\smartsniff\\smsniff|charles\\charles).exe|i(nvincea\\((browser protection\\invbrowser|enterprise\\invprotect).exe|threat analyzer\\fips\\nss\\lib\\ssl3.dll)|einspector\\(httpanalyzerfullv(6\\hookwinsockv6|7\\hookwinsockv7)|iewebdeveloperv2\\iewebdeveloperv2).dll)|geo(edge\\geo(vpn\\bin\\geovpn|proxy\\geoproxy).exe|surf by biscience toolbar\\tbhelper.dll)|s(oftperfect network protocol analyzer\\snpa.exe|andboxie\\sbiedll.dll)|(adclarity toolbar\\tbhelper|httpwatch\\httpwatch).dll|fiddler(coreapi\\fiddlercore.dll|2?\\fiddler.exe)))|windows\\system32\\(drivers\\(tm(actmon|evtmgr|comm|tdi)|nv(hda(32|64)v|lddmkm)|bd(sandbox|fsfltr)|p(ssdklbf|rl_fs)|e(amonm?|hdrv)|v(boxdrv|mci)|hmpalert).sys|(p(rxerdrv|capwsp)|socketspy).dll|v(boxservice|mu?srvc).exe)|python(3[45]|27)\\python.exe)|(h(ookwinsockv[67]|ttpwatch)|s(b(ie|ox)dll|ocketspy)|p(rxerdrv|capwsp)|xproxyplugin|mbae).dll|inv(guestie.dll(\/icon.png)?|redirhostie.dll)|w\/icon.png)/ nocase ascii wide */


    condition:
       // any of ($vid*) and #antisec > 20
        any of ($vid*) 
}

rule AdGholas_mem_antisec_M2
{
 
    meta:
        malfamily = "AdGholas"
        ref = "https://www.proofpoint.com/us/threat-insight/post/massive-adgholas-malvertising-campaigns-use-steganography-and-file-whitelisting-to-hide-in-plain-sight"

    strings:
        $s1 = "ActiveXObject(\"Microsoft.XMLDOM\")" nocase ascii wide
        $s2 = "loadXML" nocase ascii wide fullword
        $s3 = "parseError.errorCode" nocase ascii wide
        $s4 = /res\x3a\x2f\x2f[\x27\x22]\x2b/ nocase ascii wide
        $s5 = /\x251e3\x21\s*\x3d\x3d\s*[a-zA-Z]+\x3f1\x3a0/ nocase ascii wide

    condition:
        all of ($s*)
}

rule AdGholas_mem_MIME_M2
{

    meta:
        malfamily = "AdGholas"
        ref = "https://www.proofpoint.com/us/threat-insight/post/massive-adgholas-malvertising-campaigns-use-steganography-and-file-whitelisting-to-hide-in-plain-sight"

    strings:
        $s1 = "halog" nocase ascii wide fullword
        $s2 = "pcap" nocase ascii wide fullword
        $s3 = "saz" nocase ascii wide fullword
        $s4 = "chls" nocase ascii wide fullword
        $s5 = /return[^\x3b\x7d\n]+href\s*=\s*[\x22\x27]\x2e[\x27\x22]\s*\+\s*[^\x3b\x7d\n]+\s*,\s*[^\x3b\x7d\n]+\.mimeType/ nocase ascii wide
        $s6 = /\x21==[a-zA-Z]+\x3f\x210\x3a\x211/ nocase ascii wide

 condition:
     all of ($s*)
}
