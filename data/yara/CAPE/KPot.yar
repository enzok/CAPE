rule KPot
{
    meta:
        author = "enzo"
        description = "KPot Stealer"
        cape_type = "KPot Stealer"
    strings:
        $str1 = "regbot.php"
        $str2 = ".bit"
        $str3 = "D877F783D5D3EF8C" nocase
        $str4 = "bot_id=%s&x64=%d&is_admin=%d&IL=%d&os_version=%d"
    condition:
        all of them
}