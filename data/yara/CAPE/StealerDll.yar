rule StealerDll
{
    meta:
      author = "enzok"
      description = "Stealer Dll Payload"
      cape_type = "Stealer Dll Payload"

    strings:
        $cb1 = { FF 35 [4] FF 35 [4] 8D 05 [4] 50 E8 [4] 8D 44 [2] 50 E8 [4] 8B 54 [2] FF 35 [4] 52 E8 [4] 8B 54 [2] 52 E8 [4] 8B 54 [2] 52 E8 [4] 8B 54 [2] 52 E8 [4] 8B 54 [2] 52 E8 [4] 8B 54 [2] 52 E8 [4] 8D 44 [2] 50 E8 [4] 8D 15 [4] 8D 4C [2] E8 }
        $cb2 = "DllRegisterServer"

    condition:
        uint16(0) == 0x5A4D and all of ($cb*)
}