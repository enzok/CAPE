rule JBitfrost
{
    meta:
	    author = " Lorenzo Kucaric"
	    maltype = "Remote Access Trojan"
	    filetype = "jar"
        cape_type = "JBitfrost Payload"

    strings:
	    $jar = "META-INF/MANIFEST.MF"

        $txt1 = "test.txt"
        $txt2 = "ID.txt"

    condition:
        $jar and all of ($txt*)
}