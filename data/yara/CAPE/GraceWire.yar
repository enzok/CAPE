rule GraceWire
{
    meta:
        author = "enzok"
        description = "GraceWire Payload"
        cape_type = "GraceWire Payload"
    strings:
        $cmd1 = ".?AVGraceWireClient@@"
        $cmd2 = ".?AVGraceWireGeneric@@"
        $cmd3 = ".?AVGraceWireClientConnectionThread@@"
        $cmd4 = ".?AVGraceWireGenericConnectionThread@@"
    condition:
        //check for MZ Signature at offset 0
        uint16(0) == 0x5A4D and ($cmd1 and $cmd2 and $cmd3)
}