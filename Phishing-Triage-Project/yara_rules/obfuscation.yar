rule base64_obfuscation {
    meta:
        description = "Detects heavy base64 obfuscation"
        severity = "medium"
    
    strings:
        $b64 = /[A-Za-z0-9+\/]{100,}={0,2}/
        $func1 = "atob(" nocase
        $func2 = "btoa(" nocase
        $func3 = "base64" nocase
        $func4 = "fromCharCode" nocase
    
    condition:
        #b64 > 3 or (2 of ($func*))
}

rule url_encoding_obfuscation {
    meta:
        description = "Detects excessive URL encoding"
        severity = "medium"
    
    strings:
        $enc = /%[0-9A-Fa-f]{2}(%[0-9A-Fa-f]{2}){5,}/
        $dbl = /%25[0-9A-Fa-f]{2}/
        $uni = /\\u00[0-9A-Fa-f]{2}/
    
    condition:
        #enc > 5 or #dbl > 2 or #uni > 10
}

rule html_entity_obfuscation {
    meta:
        description = "Detects HTML entity encoding for obfuscation"
        severity = "low"
    
    strings:
        $num = /&#x?[0-9a-fA-F]{2,4};/
    
    condition:
        #num > 10
}

rule string_concatenation_obfuscation {
    meta:
        description = "Detects string splitting/concatenation for evasion"
        severity = "medium"
    
    strings:
        $concat1 = /\"[a-z]{1,3}\"\+\"[a-z]{1,3}\"\+\"[a-z]{1,3}\"/
        $concat2 = /\'[a-z]{1,3}\'+\'[a-z]{1,3}\'+\'[a-z]{1,3}\'/
        $arr1 = "split(" nocase
        $arr2 = "join(" nocase
        $arr3 = /\[\"[a-z]\"\,\"[a-z]\"\,\"[a-z]\"\]/
    
    condition:
        #concat1 > 3 or #concat2 > 3 or (2 of ($arr*))
}
