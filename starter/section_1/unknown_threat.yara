rule North_Udan_detector {
        meta:
                Author = "@SoheilSahraei"
                Description = "This rule detects malicious code designed by North Udan"
        strings:
                $URL = "darkl0rd.com" nocase
        condition:
                $URL

}

