rule GraceWire
{
    meta:
        author = "enzok"
        description = "GraceWire Payload"
        cape_type = "GraceWire Payload"
    strings:
        $cmd1 = "service is going to be stopped"
        $cmd2 = "exit, already loaded"
        $cmd3 = "error, call image entry"
        $cmd4 = "GraceWireClient"
    condition:
        //check for MZ Signature at offset 0
        uint16(0) == 0x5A4D and ($cmd1 and $cmd2 and $cmd3 and $cmd4)
}