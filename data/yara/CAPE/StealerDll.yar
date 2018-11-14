rule StealerDll
{
    meta:
      author = "enzok"
      description = "Stealer Dll Payload"
      cape_type = "Stealer Dll Payload"

    strings:
        $cb1 = { 53 BA 07 00 00 00 83 EC 04 C7 04 24 00 00 00 00 4A 75 F3 8B 44 24 2C A3 [4] 8B 54 24 24 8D 0C 24 E8 [4] 8B 54 24 28 8D 4C 24 04 E8 [4] 8B 54 24 04 }
        $cb2 = { 31 C9 E8 [4] 0F 85 ?? 01 00 00 [-] FF 35 [4] FF 35 [4] 8D 15 [4] 52 [-] FF 74 24 04 E8 [4] FF 74 24 10 E8 [4] FF 34 24 E8 [4] 83 C4 1C 5B C2 08 00 }

    condition:
        uint16(0) == 0x5A4D and all of ($cb*)
}