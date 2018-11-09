rule StealerDll
{
    meta:
      author = "enzok"
      description = "Stealer Dll Payload"
      cape_type = "Stealer Dll Payload"

	strings:
		$cb1 = { FF 35 ?? 39 07 10 FF 35 C0 36 07 10 8D 05 ?? ?? 03 10 50 E8 ?? E1 00 00 8D 44 24 3C 50 E8 90 56 01 00 }
		$cb2 = { 8B 54 24 0C FF 35 B4 39 07 10 52 E8 00 57 01 00 8B 54 24 48 52 E8 F6 56 01 00 8B 54 24 3C 52 E8 EC 56 }
		$cb3 = { 01 00 8B 54 24 1C 52 E8 E2 56 01 00 8B 54 24 4C 52 E8 D8 56 01 00 8B 54 24 3C 52 E8 CE 56 01 00 8D 44 }
		$cb4 = { 24 10 50 E8 44 56 01 00 8D 15 ?? 30 03 10 8D 4C 24 38 E8 1D 0E 01 00 8D 15 ?? 30 03 10 8D 4C 24 18 E8 0E 0E 01 00 }
		$cb5 = { 68 00 00 00 00 E8 6A 17 FF FF 50 E8 ?? ?? FF FF E8 ?? ?? FF FF E8 ?? ?? FE FF 31 C0 }
		$cb6 = { 53 8B 1D ?? ?? 07 10 21 DB 74 05 E8 4C 68 00 00 31 C0 5B C3 }

	condition:
		uint16(0) == 0x5A4D and all of ($cb*)
}