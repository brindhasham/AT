rule fake_login_page_indicator {
    meta:
        description = "Detects indicators of credential harvesting pages"
        severity = "high"
    
    strings:
        $form1 = "<form" nocase
        $pass = "type=\"password\"" nocase
        $pass2 = "type='password'" nocase
        $action1 = "action=\"http" nocase
        $action2 = "action='http" nocase
        $brand1 = "microsoft" nocase
        $brand2 = "office365" nocase
        $brand3 = "amazon" nocase
        $brand4 = "apple" nocase
        $brand5 = "paypal" nocase
        $brand6 = "bank" nocase
        $brand7 = "chase" nocase
        $brand8 = "wells fargo" nocase
    
    condition:
        $form1 and ($pass or $pass2) and 
        (any of ($action*) or any of ($brand*))
}

rule oauth_phishing {
    meta:
        description = "Detects OAuth consent phishing attempts"
        severity = "high"
    
    strings:
        $oauth1 = "oauth" nocase
        $oauth2 = "authorize" nocase
        $oauth3 = "consent" nocase
        $scope1 = "scope=" nocase
        $scope2 = "mail.read" nocase
        $scope3 = "user.read" nocase
        $scope4 = "files.read" nocase
        $app1 = "mail sync" nocase
        $app2 = "document sharing" nocase
        $app3 = "secure message" nocase
    
    condition:
        2 of ($oauth*) and any of ($scope*) and any of ($app*)
}

rule html_credential_form {
    meta:
        description = "Detects HTML forms designed to steal credentials"
        severity = "high"
    
    strings:
        $html = "<html" nocase
        $form = "<form" nocase
        $field1 = "name=\"email\"" nocase
        $field2 = "name=\"username\"" nocase
        $field3 = "name=\"password\"" nocase
        $field4 = "id=\"password\"" nocase
        $field5 = "placeholder=\"password\"" nocase
        $obf1 = "fromCharCode" nocase
        $obf2 = "unescape" nocase
        $obf3 = "eval(atob" nocase
        $obf4 = "String.fromCharCode" nocase
    
    condition:
        $html and $form and (2 of ($field*)) and any of ($obf*)
}
