#  Phishing Email Analyzer with YARA Integration

**This is nn automated phishing email triage tool that analyzes `.eml` files for indicators of phishing, calculates a weighted risk score, maps findings to MITRE ATT&CK techniques, and logs all results to a Google Sheet for team-based investigation.**

---
##  Features

| Category | Capability |
|----------|-----------|
| **Email Parsing** | **Full RFC 5322(internet message format) `.eml` parsing including multipart MIME, encoded headers, and nested content** |
| **Authentication** | **SPF, DKIM, and DMARC result extraction with normalization** |
| **URL Analysis** | **Extraction, defanging (scheme + domain only), and URL shortener detection**|
| **YARA Scanning** | **Body and attachment scanning against custom YARA rule sets** |
| **Attachment Analysis** | **SHA-256 hashing, executable/suspicious extension detection, per-attachment YARA scanning** |
| **IP Extraction** | **Originating sender IP from `Received` headers with RFC private range filtering** |
| **Risk Scoring** | **Configurable weighted scoring with automatic verdict assignment** |
| **MITRE Mapping** | **Findings mapped to MITRE ATT&CK technique IDs** |
| **Google Sheets** | **Automatic export to a shared Google Sheet for collaborative triage** |

---

## Design
- **The analyzer has 6 parts**
- **`EmailExtractor`- Email Extraction : This fucntions to Hparse headers, extract body, URL, IP, base64 detection**
- **`AuthResults` - Authentication: This functions for SPF/DKIM/DMARC parsing and normalization**
- **`AttachmentAnalyzer` - Attachments: This function contributes to File hashing, extension checking, per-file YARA scanning**
- **`RiskAssessment`- Risk Scoring: This performs Weighted score calculation, verdict, MITRE mapping**
- **`SheetManager`- Sheet Manager: This cheks for Google Sheets authentication, header management, row appending**
- **`PhishingAnalyzer` Orchestrator: Finally, this coordinates all components end-to-end**

---

## Risk Scoring

### Indicator Weights

| **Indicator** | **Weight** |
|---------------|------------|
| **SPF fail/softfail** | **2** |
| **DKIM fail/none** | **2** |
| **DMARC fail** | **3** |
| **Reply-To domain mismatch** | **3** |
| **Base64 encoded content** | **1** |
| **Contains URLs** | **1** |
| **URL shortener used** | **2** |
| **YARA rule match (body or attachment)** | **3** |
| **Suspicious attachment extension** | **2** |
| **Executable attachment** | **4** |

### **Verdicts**

| **Score** | **Verdict** |
|-----------|------------|
| **0 – 1** | **Clean** |
| **2 – 4** | **Suspicious** |
| **5+** | **Likely Phishing** |

### **Authentication Normalization**

Raw auth results are normalized to a standard set:

| **Raw Values** | **Normalized** |
|----------------|---------------|
| **`pass`, `pass+`** | **`PASS`** |
| **`fail`, `softfail`** | **`FAIL`** |
| **`neutral`** | **`NEUTRAL`** |
| **`none`** | **`NONE`** |
| **`unknown`** | **`UNKNOWN`** |
| **`error`, `temperror`, `permerror`** | **`ERROR`** |

---

## ** MITRE ATT&CK Mapping**

| **Technique ID** | **Name** | **Triggered By** |
|------------------|----------|------------------|
| **`T1566.001`** | **Spearphishing Attachment** | **Executable or suspicious attachments** |
| **`T1566.002`** | **Spearphishing Link** | **SPF/DKIM/DMARC failures, domain mismatch, URL shorteners** |
| **`T1027.001`** | **Obfuscated Files: Binary Padding** | **Base64 encoded content** |

---

## **Google Sheets Setup**

### **Step 1: Create a Google Cloud Project**

- **Go to Google Cloud Console**
- **Create a new project (or select existing)**
- **Enable these APIs:**
  - **Google Sheets API**
  - **Google Drive API**

---

### **Step 2: Create a Service Account**

- **IAM & Admin → Service Accounts → Create Service Account**
- **Name it (e.g., `phishing-analyzer`)**
- **Click Create and Continue → Done**

---

### **Step 3: Generate Credentials**

- **Click the service account → Keys tab**
- **Add Key → Create new key → JSON**
- **Save the file as `credentials.json` in the project root**

---

### **Step 4: Create and Share the Spreadsheet**

- **Create a Google Sheet named exactly: `Phishing_Triage`**
- **Click Share and add the service account email**
  - **(e.g., `name@project-id.iam.gserviceaccount.com`)**
- **Grant Editor access**
- **Headers are created automatically on first run**

---

### **YARA Rules Setup**
 **Create YARA Rules Directory**

bash
```mkdir -p yara_rules```

**Create index.yar**
**index.yar is the master entry point for all the YARA rules. It doesn't contain any detection rules itself. It just tells YARA which rule files to load using include statements**

**The yara files are stored in `/yara_rules` folder**

**Sample emails are stored in samples folder in project root folder in .eml format**

### **Environment setup**

**In the project root folder**
**`pip install gspread google-auth yara-python`**

## **To run the project**

**`python analyzer.py`**

**Upon running, the sample emails are analyzed and the results are stored in 'Phishing_triage' google sheet with following columns analyzed'**

**`Case_ID, File_Name, Subject, Sender, Sender_Domain, Reply_To, Reply_Domain, Domain_Mismatch, Sender_IP, URL_Count, URLs, Defanged_URLs, URL_Shortener_Used, Has_Attachment, Attachment_Count, Attachment_Names, Executable_Attachment, Attachment_SHA256s, Base64_Detected, SPF_Result, DKIM_Result, DMARC_Result, SPF_Normalized, DKIM_Normalized, DMARC_Normalized, YARA_Body_Matches, YARA_Attachment_Matches, Risk_Score, Risk_Reasons, MITRE_Techniques, Verdict`**

![](https://github.com/brindhasham/AT/blob/main/Phishing-Triage-Project/image.png)
