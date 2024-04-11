rule North_Udan_detector {
        meta:
                Author = "@SoheilSahraei"
                Description = "This rule detects malicious code designed by North Udan"
        strings:
                $script1 = "SSH-T" nocase
                $script2 = "SSH-One" nocase
                $URL = "darkl0rd.com" nocase
		$port = "7758"
        condition:
                $script1 and $script2 and $URL and $port

}
