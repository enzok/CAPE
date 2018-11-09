rule StealerDll
{
    meta:
      author = "enzok"
      description = "Stealer Dll Payload"
      cape_type = "Stealer Dll Payload"

    strings:
        $cb1 = { FF 35 [4] FF 35 [4] 8D 05 [4] 50 E8 [4] 8D 44 24 3C 50 E8 [4] 8B 54 24 0C FF 35 [4] 52 E8 [4] 8B 54 \
         24 48 52 E8 [4] 8B 54 24 3C 52 E8 [4] 8B 54 24 1C 52 E8 [4] 8B 54 24 4C 52 E8 [4] 8B 54 24 3C 52 E8 [4] 8D 44 \
         24 10 50 E8 [4] 8D 15 [4] 8D 4C 24 38 E8 [4] 8D 15 [4] 8D 4C 24 18 E8 [4] 8D 15 }
        $cb2 = { 68 [4] E8 [4] 50 E8 [4] E8 [4] E8 [4] 31 C0 }
        $cb3 = { 53 8B 1D [4] 21 DB 74 05 E8 [4] 31 C0 5B C3 }
        $cb4 = "DllRegisterServer"

    condition:
        uint16(0) == 0x5A4D and all of ($cb*)
}