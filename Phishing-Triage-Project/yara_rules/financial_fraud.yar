rule wire_transfer_fraud {
    meta:
        description = "Detects wire transfer/BEC fraud indicators"
        severity = "high"
        category = "business_email_compromise"
    
    strings:
        $wire1 = "wire transfer" nocase
        $wire2 = "bank transfer" nocase
        $wire3 = "swift transfer" nocase
        $wire4 = "ach transfer" nocase
        
        $urg1 = "urgent" nocase
        $urg2 = "immediately" nocase
        $urg3 = "asap" nocase
        $urg4 = "time sensitive" nocase
        
        $chg1 = "new account" nocase
        $chg2 = "updated banking" nocase
        $chg3 = "account information" nocase
        $chg4 = "routing number" nocase
        $chg5 = "sort code" nocase
        
        $byp1 = "don't call" nocase
        $byp2 = "in meetings" nocase
        $byp3 = "unavailable" nocase
        $byp4 = "only email" nocase
    
    condition:
        any of ($wire*) and any of ($urg*) and any of ($chg*) and any of ($byp*)
}

rule invoice_fraud {
    meta:
        description = "Detects fake invoice scams"
        severity = "medium"
    
    strings:
        $inv1 = "invoice" nocase
        $inv2 = "payment due" nocase
        $inv3 = "outstanding balance" nocase
        $inv4 = "remittance" nocase
        
        $pres1 = "attached" nocase
        $pres2 = "enclosed" nocase
        $pres3 = "please find" nocase
        
        $act1 = "pay now" nocase
        $act2 = "click to pay" nocase
        $act3 = "payment link" nocase
    
    condition:
        any of ($inv*) and any of ($pres*) and any of ($act*)
}

rule cryptocurrency_scam {
    meta:
        description = "Detects cryptocurrency-related scams"
        severity = "medium"
    
    strings:
        $crypto1 = "bitcoin" nocase
        $crypto2 = "btc" nocase
        $crypto3 = "ethereum" nocase
        $crypto4 = "eth" nocase
        $crypto5 = "wallet" nocase
        $crypto6 = "blockchain" nocase
        
        $scam1 = "double your" nocase
        $scam2 = "guaranteed return" nocase
        $scam3 = "send 1 get 2" nocase
        $scam4 = "elon musk" nocase
        $scam5 = "giveaway" nocase
        
        $addr = /(bc1|[13])[a-zA-HJ-NP-Z0-9]{25,62}/
        $eth_addr = /0x[a-fA-F0-9]{40}/
    
    condition:
        any of ($crypto*) and any of ($scam*) and ($addr or $eth_addr)
}

rule gift_card_fraud {
    meta:
        description = "Detects gift card scam requests"
        severity = "medium"
    
    strings:
        $gift1 = "gift card" nocase
        $gift2 = "itunes card" nocase
        $gift3 = "amazon card" nocase
        $gift4 = "google play" nocase
        $gift5 = "steam card" nocase
        
        $req1 = "purchase" nocase
        $req2 = "buy" nocase
        $req3 = "get" nocase
        $req4 = "need" nocase
        
        $sec1 = "scratch" nocase
        $sec2 = "code" nocase
        $sec3 = "send me" nocase
        $sec4 = "photo" nocase
        $sec5 = "picture" nocase
    
    condition:
        any of ($gift*) and any of ($req*) and any of ($sec*)
}
