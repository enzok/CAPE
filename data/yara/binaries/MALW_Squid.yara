rule SQUID_WHITE
{
    meta:
        author = "Todd Towles"
        last_modified = "2017-08-28"

    strings:
        $re1 = /<script>function \w+[(]\w+[,] \w+[)]/ nocase
        $re2 = /for [(]\w+ [=] \w+[.]length [-] 1/ nocase
        $re3 = /return new ActiveXObject[(]\w+[)]/ nocase
        $re4 = /catch[(]\w+[)]/ nocase

    condition:
        all of them
}

rule SQUID_GATE
{
    meta:
        author = "Todd Towles"
        last_modified = "2017-08-28"

    strings:
        $re1 = /function \w+[(]\w+[,] \w+[)]/ nocase
        $re2 = /for [(]\w+ [=] \w+[.]length [-] 1/ nocase
        $re4 = /catch[(]\w+[)]/ nocase

    condition:
        all of them
}
