rule TrickBot
{
    meta:
        author = "sysopfb"
        description = "TrickBot Payload"
        cape_type = "TrickBot Payload"
    strings:
        $ua1 = "TrickLoader" ascii wide
        $ua2 = "TrickBot" ascii wide
        $ua3 = "BotLoader" ascii wide
        $str1 = "<moduleconfig>*</moduleconfig>" ascii wide
        $str2 = "group_tag" ascii wide
        $str3 = "client_id" ascii wide
        $code1 = {8A 11 88 54 35 F8 46 41 4F 89 4D F0 83 FE 04 0F 85 7E 00 00 00 8A 1D ?? ?? ?? ?? 33 F6 8D 49 00 33 C9 84 DB 74 1F 8A 54 35 F8 8A C3 8D 64 24 00}
        $code2 = {8A 45 FD 8A 4D FC 8A 55 FD 8B 7D F8 83 45 F8 03 C0 F8 04 C0 E1 02 24 03 02 C1 88 45 08 8A 45 FE 8A C8 C0 F9 02 C0 E0 06 02 45 FF 80 E1 0F C0 E2 04 32 CA 88 4D 09 88 45 0A 8D 75 08 66 A5 A4}
    condition:
        any of ($ua*) or all of ($str*) or any of ($code*)
}
