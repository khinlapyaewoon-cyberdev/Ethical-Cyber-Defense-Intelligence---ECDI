# 🔒 Ethical Cyber Defense Intelligence (ECDI)

**Defensive Recon + LLaMA Analysis Streamlit App**

ECDI is a **defensive-only cybersecurity tool** designed to analyze reconnaissance `.txt` files, detect vulnerability indicators, and provide actionable remediation and next steps — all without generating exploits or offensive payloads.

> ⚠️ **Warning:** Use only on systems you own or are explicitly authorized to test.

---

## 🧠 Features

- **Static Pattern Detection**: CVEs, sensitive tokens, exposed paths, weak TLS, misconfigurations, debug info, and more.
- **Tech & CDN Detection**: Identify frameworks (WordPress, Django, React, etc.) and CDN usage (Cloudflare, AWS CloudFront, Akamai, etc.).
- **Port & Service Analysis**: Detect open HTTP/HTTPS ports and other sensitive ports.
- **CVE Correlation**: Best-effort Exploit-DB scraping + fallback links to NVD, CVE.org, and GitHub.
- **LLaMA-Powered Reports**: 
  - Full remediation report with risk levels, evidence, remediation, and hardening steps.
  - Next Steps guidance: Immediate, Short-Term, and Long-Term defensive actions.
- **Streamlit Dashboard**: Interactive interface with collapsible source line views.
- **Downloadable Results**: Full report and detections exportable as `.txt`.

---

## ⚙️ Installation

```bash
pip install streamlit pandas requests beautifulsoup4 huggingface_hub

▶️ Usage
streamlit run app.py

Upload a reconnaissance .txt file.

Configure Hugging Face token:

Use embedded token (default) or provide your own.

Select LLaMA report options (Full Report / Next Steps).

Review detected indicators, CVEs, and recommendations.

Download the professional results .txt.
---

🔍 Detection Categories
Vulnerability Indicators: CVE references, misconfigurations, exposed files.

Sensitive Tokens: AWS/GCP keys, JWTs, default credentials.

TLS & Security Headers: Weak TLS versions, missing HSTS, CSP, X-Frame-Options.

Framework & Tech Stack: Detect web frameworks and libraries.

Ports & Services: Open HTTP/HTTPS and other suspicious ports.

Cloud Metadata & Storage: AWS, GCP, Azure metadata endpoints, S3 buckets, Google Cloud Storage.

Source Lines: Evidence for each detected pattern included in report.
---

🧩 How It Works?

Recon TXT File
      ↓
Static Pattern Detection (Regex & Heuristics)
      ↓
CVE Mapping & ExploitDB Correlation
      ↓
Risk Analysis & Evidence Extraction
      ↓
LLaMA Full Report & Next Steps
      ↓
Streamlit Dashboard & TXT Export
---

👤 Author
Khin La Pyae Woon
AI-Enhanced Ethical Hacking | Cybersecurity | Digital Forensic | Analyze | Developing

🌐 Portfolio: https://khinlapyaewoon-cyberdev.vercel.app
🔗 LinkedIn: www.linkedin.com/in/khin-la-pyae-woon-ba59183a2
💬 WhatsApp: https://wa.me/qr/MJYX74CQ5VA4D1

📜 License & Ethics
This tool is released for educational, defensive, and research purposes only.

Any offensive or unauthorized usage is strictly prohibited.
