rule suspicious_office_macro {
    meta:
        description = "Detects malicious Office documents"
        severity = "high"
    
    strings:
        $ole = { D0 CF 11 E0 A1 B1 1A E1 }
        $zip = { 50 4B 03 04 }
        $macro = "vbaProject.bin" nocase
        $auto1 = "AutoOpen" nocase
        $auto2 = "Document_Open" nocase
        $auto3 = "Workbook_Open" nocase
    
    condition:
        ($ole at 0 or $zip at 0) and ($macro or any of ($auto*))
}

rule suspicious_pdf {
    meta:
        description = "Detects suspicious PDFs"
        severity = "medium"
    
    strings:
        $pdf = "%PDF"
        $js = "/JavaScript" nocase
        $js2 = "/JS" nocase
        $action = "/OpenAction" nocase
    
    condition:
        $pdf at 0 and any of ($js, $js2, $action)
}

rule suspicious_script_attachment {
    meta:
        description = "Detects script files"
        severity = "high"
    
    strings:
        $ps1 = "powershell" nocase
        $ps2 = "Invoke-Expression" nocase
        $ps3 = "DownloadString" nocase
        $js1 = "WScript" nocase
        $js2 = "ActiveXObject" nocase
        $js3 = "eval(" nocase
        $vbs1 = "CreateObject" nocase
        $vbs2 = "WScript.Shell" nocase
    
    condition:
        2 of them
}

rule iso_img_attachment {
    meta:
        description = "Detects ISO/IMG files"
        severity = "medium"
    
    strings:
        $iso = { 43 44 30 30 31 }
    
    condition:
        $iso at 0x8001 or $iso at 0x8801 or $iso at 0x9001
}
