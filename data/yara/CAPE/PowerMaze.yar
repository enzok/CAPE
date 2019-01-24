rule PowerMaze
{
    meta:
        author = "@enzok"
        description = "PowerMaze Payload"
        cape_type = "PowerMaze Payload"
    strings:
        $string1 = "FromBase64String('QwBPAE4ATgBFAEMAVAA=')))"
        $string2 = "FromBase64String('RgBJAEwARQBfAFIARQBRAFUARQBTAFQA')))"
        $string3 = "FromBase64String('QwBNAEQAXwBSAEUAUQBVAEUAUwBUAA==')))"
        $string4 = "FromBase64String('UABSAE8AQwBFAFMAUwBfAFIARQBRAFUARQBTAFQA')))"
        $string5 = "FromBase64String('UgBFAEcASQBTAFQAUgBZAF8AUgBFAFEAVQBFAFMAVAA=')))"
        $string6 = "FromBase64String('UwBDAFIARQBFAE4AXwBSAEUAUQBVAEUAUwBUAA==')))"
        $string7 = "FromBase64String('SwBFAFkAQgBPAEEAUgBEAF8AUgBFAFEAVQBFAFMAVAA=')))"
        $string8 = "FromBase64String('VQBQAEwATwBBAEQAXwBSAEUAUQBVAEUAUwBUAA==')))"
        $string9 = "FromBase64String('RgBJAEwARQBfAFUATgBaAEkAUABfAFIARQBRAFUARQBTAFQA')))"
        $string10 = "FromBase64String('RABPAFcATgBMAE8AQQBEAF8AUgBFAFEAVQBFAFMAVAA=')))"
        $string11 = "FromBase64String('RgBJAEwARQBfAFoASQBQAF8AUgBFAFEAVQBFAFMAVAA=')))"
        $string12 = "FromBase64String('SwBFAFkAQgBPAEEAUgBEAF8AUwBUAE8AUAA=')))"

    condition:
        8 of ($string*)
}