rule Ursnif
{
    meta:
        author = "kevoreilly"
        description = "Ursnif Payload"
        cape_type = "Ursnif Payload"
    strings:
        $a1 = {8D 7D ?? AB 66 AB 6A 08 AA 68 [4] 8D ?? ?? 5?}
        $a2 = "Tape Device" fullword
        $a3 = "ASCIT8" fullword
        $a4 = "IEEE 1394"
        $a5 = ".bss"
    condition:
        uint16(0) == 0x5A4D and (all of ($a*))
}
