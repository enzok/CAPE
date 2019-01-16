rule Monsoon_BADNEWS
{
  meta:
    author = "EMH FW"
  strings:
    $mz       = "MZ"
    $delay    = { 8? C6 99 F7 F9 85 D2 74 05 41 3B CF 7E F2 3B CE 75 0F
56 68 ?? ?? ?? ?? E8 ?? F8 FF FF 83 C4 08 43 46 81 FB 80 38 01 00 7E C6 }
    $encoded1 = "lfsofm43/emm"
    $encoded2 = "bewbqj43/emm"
    $encoded3 = "ouemm/emm"
    $decoder  = { C0 E0 0? 02 C1 34 ?? C0 C0 ?? 88 04 }
  condition:
    $mz at 0 and all of ($encoded*) and ($delay or $decoder) }


rule Monsoon_RTF_Dropper
{
  meta:
    author = "EMH FW"
    note   = "Actor likely using generic CVE-2015-1642 described here https://www.greyhathacker.net/?p=911"
  strings:
    $rtf  = { 7B 5C 72 74 66 31 5C 61 64 65 66 6C 61 6E 67 31 30 32 35 5C 61 6E 73 69 5C 61 6E 73 69 63 70 67 31 32 35 32 5C 75 63 31 5C }
    $pk   =  "504b0304"
    $ax1  =  "776f72642f616374697665582f61637469766558312e62696e"
    $ax2  =  "776f72642f616374697665582f61637469766558322e62696e"
    $xml1 = { 3631363337343639373636353538????????3265373836643663 }

  condition:
    $rtf at 0 and $pk and all of ($ax*) and #xml1 >  200 }
