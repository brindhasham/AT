rule phishing_urgency_language {
    meta:
        description = "Detects urgency-based social engineering phrases"
        severity = "medium"
    
    strings:
        $urg1 = "immediate action required" nocase
        $urg2 = "account will be suspended" nocase
        $urg3 = "account suspended" nocase
        $urg4 = "verify your account" nocase
        $urg5 = "unusual activity" nocase
        $urg6 = "unusual signin activity" nocase
        $urg7 = "confirm your identity" nocase
        $urg8 = "limited time" nocase
        $urg9 = "act now" nocase
        $urg10 = "security alert" nocase
        $urg11 = "password expires" nocase
        $urg12 = "unauthorized access" nocase
        $urg13 = "expirando" nocase
        $urg14 = "pontos expirando" nocase
        $urg15 = "hoje" nocase
        $urg16 = "microsoft account" nocase
        $urg17 = "signin activity" nocase
        $urg18 = "schnellen gewichtsverlust" nocase
        $urg19 = "schlankheitssystem" nocase
    
    condition:
        2 of them
}

rule phishing_generic_greeting {
    meta:
        description = "Detects generic greetings"
        severity = "low"
    
    strings:
        $g1 = "Dear Customer" nocase
        $g2 = "Dear User" nocase
        $g3 = "Dear Valued Customer" nocase
        $g4 = "Dear Account Holder" nocase
        $g5 = "Dear Member" nocase
        $g6 = "Dear Client" nocase
    
    condition:
        any of them
}

rule phishing_credential_request {
    meta:
        description = "Detects credential requests"
        severity = "high"
    
    strings:
        $req1 = "enter your password" nocase
        $req2 = "provide your credentials" nocase
        $req3 = "confirm your password" nocase
        $req4 = "update your payment information" nocase
        $req5 = "verify your credit card" nocase
        $ctx1 = "click here" nocase
        $ctx2 = "click below" nocase
        $ctx3 = "clique aqui" nocase
        $ctx4 = "hier klicken" nocase
    
    condition:
        any of ($req*) or any of ($ctx*)
}

rule phishing_fake_brand {
    meta:
        description = "Detects brand impersonation"
        severity = "medium"
    
    strings:
        $brand1 = "microsoft" nocase
        $brand2 = "office365" nocase
        $brand3 = "amazon" nocase
        $brand4 = "apple" nocase
        $brand5 = "paypal" nocase
        $brand6 = "google" nocase
        $brand7 = "bradesco" nocase
        $brand8 = "livelo" nocase
        $brand9 = "banco" nocase
        $brand10 = "otto" nocase
    
    condition:
        any of them
}

rule phishing_suspicious_domain {
    meta:
        description = "Detects suspicious domain patterns"
        severity = "high"
    
    strings:
        $dom1 = "access-accsecurity.com" nocase
        $dom2 = "atendimento.com.br" nocase
        $dom3 = "winner-win.art" nocase
        $dom4 = "firiri.shop" nocase
        $dom5 = "thebandalisty.com" nocase
        $dom6 = "seguimentmydomaine2bra.me" nocase
    
    condition:
        any of them
}

rule phishing_url_shortener {
    meta:
        description = "Detects URL shortener usage"
        severity = "medium"
    
    strings:
        $short1 = "bit.ly" nocase
        $short2 = "t.co" nocase
        $short3 = "tinyurl.com" nocase
        $short4 = "goo.gl" nocase
        $short5 = "ow.ly" nocase
    
    condition:
        any of them
}
