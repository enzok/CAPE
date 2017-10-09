rule Dreambot
{
    meta:
        author = "kevoreilly"
        description = "Dreambot Payload"
        cape_type = "Dreambot Payload"
    strings:
        $a1 = {8D 7D ?? AB 66 AB 6A 08 AA 68 [4] 8D ?? ?? 5?}
        $b0 = "vmware" fullword
        $b1 = "vbox" fullword
        $b2 = "virtual hd" fullword
        $b4 = "qemu" fullword
        $b5 = "c:\\321.txt" fullword
        $b6 = ".bss"
        $b7 = "Tape Device" fullword
        $b8 = "ASCIT8" fullword
        $b9 = "IEEE 1394"
    condition:
        uint16(0) == 0x5A4D and (1 of ($a*)) and (all of ($b*))
}
