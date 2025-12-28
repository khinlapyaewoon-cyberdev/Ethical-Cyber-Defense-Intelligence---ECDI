#!/usr/bin/env python3
# defensive_with_ai.py
"""
Defensive Recon + LLaMA analysis Streamlit app

- Static regex detection (patterns from user's script)
- Populates FEATURES flags & source_lines
- Best-effort Exploit-DB search + fallback links for CVEs
- LLaMA remediation using Hugging Face InferenceClient (meta-llama/Llama-3.1-8B-Instruct)
  - Embedded HF token option (per user choice)
  - Runs two passes: deterministic + stochastic (user-configurable)
  - Displays outputs read-only (no duplicate text areas)
  - Generates separate "Next Steps" (Immediate / Short / Long) via LLaMA
Note: Defensive-only tool. Only analyze targets you own or are authorized to test.
"""

from __future__ import annotations
import os
import re
import json
import time
import traceback
from typing import Any, Dict, List

import streamlit as st

# optional network libs for exploit-db scraping
try:
    import requests
    from bs4 import BeautifulSoup
except Exception:
    requests = None
    BeautifulSoup = None

# huggingface client (required for LLaMA calls)
try:
    from huggingface_hub import InferenceClient
    from huggingface_hub.utils import hf_raise_for_status
except Exception:
    InferenceClient = None

# -------------------------
# Embedded HF token (user requested embedded key)
HF_TOKEN_EMBEDDED = "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"

# LLaMA model used (preserve your original)
LLaMA_MODEL = "meta-llama/Llama-3.1-8B-Instruct"
JSON_MARKER = "### JSON OUTPUT ###"
NEXT_STEPS_MARKER = "### NEXT STEPS JSON ###"

# -------------------------
# Patterns, FEATURES, TECH_PATTERNS, CDN_PATTERNS
# (kept exactly as provided)
PATTERNS = {
    "cve": re.compile(r"CVE-\d{4}-\d{4,7}", re.IGNORECASE),
    "vuln_words": re.compile(r"(?mi)\b(VULNERABLE|potentially VULNERABLE|EXPLOIT|POC|proof[- ]?of[- ]?concept|PROOF-OF-CONCEPT)\b"),
    "tls_weakness": re.compile(r"(?mi)\b(LUCKY13|POODLE|HEARTBLEED|DROWN|LOGJAM|FREAK|ROBOT|RC4|weak cipher|CBC.*vulnerable|export ciphers|SSLv3|TLSv1\.0)\b"),
    "nse": re.compile(r"(?mi)\b(NSE: Starting|Nmap scan report|http-vuln-|ssl-heartbleed|ssl-poodle|smb-vuln-|vuln:)\b"),
    "open_ports": re.compile(r"(?m)^(\d{1,5}\/(?:tcp|udp))\s+(open|filtered)\s+([A-Za-z0-9\-\_\.\/]*)"),
    "header_hsts": re.compile(r"(?mi)^\s*strict-transport-security\s*[:=]\s*(.+)$", re.MULTILINE),
    "header_csp": re.compile(r"(?mi)^\s*content-security-policy\s*[:=]\s*(.+)$", re.MULTILINE),
    "header_xframe": re.compile(r"(?mi)^\s*x-frame-options\s*[:=]\s*(.+)$", re.MULTILINE),
    "header_xcto": re.compile(r"(?mi)^\s*x-content-type-options\s*[:=]\s*(.+)$", re.MULTILINE),
    "header_cors": re.compile(r"(?mi)^\s*Access-Control-Allow-Origin\s*[:=]\s*(.+)$", re.MULTILINE),
    "header_cors_creds": re.compile(r"(?mi)^\s*Access-Control-Allow-Credentials\s*[:=]\s*(.+)$", re.MULTILINE),
    "set_cookie": re.compile(r"(?mi)^\s*Set-Cookie:\s*(.+)$", re.MULTILINE),
    "server_banner": re.compile(r"(?mi)^\s*Server:\s*(.+)$", re.MULTILINE),
    "version_generic": re.compile(r"(?mi)\b(version|v)\s*[:=]?\s*([0-9]+\.[0-9]+(?:\.[0-9]+)?)"),
    "exposed_paths": re.compile(r"(?mi)\b(/\.git/|/wp-admin/|/wp-login\.php|/phpinfo\.php|/robots\.txt|/sitemap\.xml|/config.php|/\.env\b|/vendor/|/composer\.json|/admin/)\b"),
    "sensitive_files": re.compile(r"(?mi)(\.git\/|\.env|\.htaccess|composer\.json|package-lock\.json|WEB-INF\/web.xml)"),
    "sql_injection": re.compile(r"(?mi)\b(sqlmap|SQL\s*injection|syntax error|mysql_fetch|ORA-|SQLException|SQLSTATE)\b"),
    "xss": re.compile(r"(?mi)\b(XSS|cross[- ]site scripting|<script>|alert\(|document\.cookie|onerror=|onload=)\b"),
    "rce_lfi": re.compile(r"(?mi)\b(Local File Inclusion|Remote File Inclusion|RFI|LFI|command injection|exec\(|system\(|popen\(|/etc/passwd)\b"),
    "poc": re.compile(r"(?mi)\b(POC|proof[- ]of[- ]concept|exploit[- ]db|exploitdb|metasploit|msfconsole)\b"),
    "aws_meta": re.compile(r"(169\.254\.169\.254|169\.254\.170\.2|metadata\.amazonaws\.com)", re.IGNORECASE),
    "gcp_meta": re.compile(r"(metadata\.google\.internal|169\.254\.169\.254)", re.IGNORECASE),
    "azure_meta": re.compile(r"(169\.254\.169\.254\/metadata\/instance|management\.azure\.com)", re.IGNORECASE),
    "cloud_storage": re.compile(r"(?mi)(s3\.amazonaws\.com|s3:\/\/|\.s3\.amazonaws\.com|storage\.googleapis\.com|blob\.core\.windows\.net|digitaloceanspaces\.com|r2\.cloudflarestorage\.com)"),
    "aws_key": re.compile(r"(AKIA[0-9A-Z]{16})"),
    "gcp_key": re.compile(r"(AIza[0-9A-Za-z\-_]{35})"),
    "jwt": re.compile(r"(eyJ[A-Za-z0-9_\-]+?[.][A-Za-z0-9_\-]+?[.][A-Za-z0-9_\-]+)"),
    "basic_auth": re.compile(r"(?mi)Authorization:\s*Basic\s+[A-Za-z0-9+/=]+"),
    "default_creds": re.compile(r"(?mi)\b(admin:admin|root:root|guest:guest|administrator:password|admin:password)\b"),
    "framework_debug": re.compile(r"(?mi)\b(DEBUG=True|debug=true|Stack Trace|Exception in thread|Laravel|Django|Flask)\b"),
    "port_discovery": re.compile(r'\b(?:Discovered|open port)\s*(\d{1,5})[^\d]', re.I),
    "port_line": re.compile(r'\b(\d{1,5})/(tcp|udp)\s+(open|closed)\b', re.I),
    "tls_versions": re.compile(r'TLSv?(1\.[0-9]|2\.[0-9]|3\.[0-9])', re.I),
    "txt_re": re.compile(r'\bTXT\b', re.I),
    "spf_re": re.compile(r'v=spf1', re.I),
    "mx_re": re.compile(r'\bMX\b', re.I),
    "mitre_re": re.compile(r'\b(Execution|Privilege Escalation|Persistence|Lateral Movement|Defense Evasion|Discovery|Collection|Exfiltration|Impact)\b', re.I)
}

FEATURES = {
    'has_api_endpoints': False,
    'graphql_detected': False,
    'leaked_js_tokens_count': 0,
    'exposed_backup_files': False,
    'exposed_config_files': False,
    'has_sensitive_tokens': False,
    'aws_or_gcp_keys_exposed': False,
    'hardcoded_passwords': False,
    'robots_or_sitemap_found': False,
    'directory_listing_enabled': False,
    'uses_outdated_software': False,
    'tech_stack_detected': [],
    'framework_exposure': False,
    'cdn_usage_detected': False,
    'public_ip_exposed_in_code': False,
    'exposed_database_endpoints': False,
    'debug_mode_enabled': False,
    'exposed_api_docs': False,
    'exposed_environment_vars': False,
    'insecure_cookies': False,
    'weak_session_management': False,
    'missing_security_headers': None,
    'cloud_storage_exposed': False,
    'bucket_or_blob_exposure': False,
    'git_or_repo_leak': False,
    'open_redirect_params_count': 0,
    'cors_wildcard_detected': None,
    'open_ports_count': 0,
    'open_ports': [],
    'has_admin_port_open': False,
    'has_http_port_open': False,
    'has_https_port_open': False,
    'port_21_or_23_open': False,
    'suspicious_ports_open': False,
    'tls_versions_supported': [],
    'has_weak_tls': None,
    'missing_hsts': None,
    'ssl_expired_or_invalid': None,
    'self_signed_cert': None,
    'missing_csp': None,
    'missing_x_frame_options': None,
    'missing_xss_protection': None,
    'x_content_type_options_missing': None,
    'referrer_policy_missing': None,
    'content_security_policy_weak': False,
    'x_powered_by_header': False,
    'server_header_disclosure': False,
    'spf_strictness_score': 0,
    'spf_broken_or_excessive_includes': False,
    'txt_record_count': 0,
    'has_3rd_party_verifications': False,
    'mx_google_or_custom': False,
    'cves': set(),
    'mitre_tactics_detected': [],
    'sensitive_ports_total_score': 0,
    'exposure_score': 0,
    'source_lines': {}
}

TECH_PATTERNS = {
    'WordPress': r'\b(wp-content|wp-includes|wp-admin)\b',
    'Joomla': r'\b(Joomla!|/components/)\b',
    'Drupal': r'\bDrupal\b',
    'Magento': r'\bMagento\b',
    'React': r'\breact(\.min)?\.js\b',
    'Angular': r'\bangular(\.min)?\.js\b',
    'Vue.js': r'\bvue(\.min)?\.js\b',
    'Node.js': r'\bnode\.js\b',
    'Express.js': r'\bexpress\b',
    'Django': r'\bdjango\b',
    'Flask': r'\bflask\b',
    'Ruby on Rails': r'\bruby|rails\b',
    'Laravel': r'\blaravel\b',
    'Spring': r'\bspring\b',
    'ASP.NET': r'\basp\.net\b'
}

CDN_PATTERNS = {
    'Cloudflare': r'\bcloudflare\b',
    'AWS CloudFront': r'\bcloudfront\b',
    'Akamai': r'\b(akamaiedge|akamai)\b',
    'Fastly': r'\bfastly\b',
    'Google CDN': r'\bgoogleapis\b',
    'Azure CDN': r'\bazureedge\b'
}

# -------------------------
# Utilities: exploitdb, fallbacks, source lines
# -------------------------
EXPLOITDB_SEARCH = "https://www.exploit-db.com/search?q={query}"

def find_source_lines(text: str, pattern: re.Pattern) -> List[str]:
    return [ln.rstrip() for ln in text.splitlines() if pattern.search(ln)]

def search_exploitdb(cve: str) -> List[Dict[str, str]]:
    results: List[Dict[str, str]] = []
    if requests is None or BeautifulSoup is None:
        return results
    try:
        url = EXPLOITDB_SEARCH.format(query=requests.utils.quote(cve))
        r = requests.get(url, headers={"User-Agent": "vuln-protection-tool/1.0"}, timeout=12)
        if r.status_code != 200:
            return results
        soup = BeautifulSoup(r.text, "html.parser")
        for a in soup.select("a[href*='/exploits/']"):
            href = a.get("href")
            title = a.get_text(strip=True) or a.get('title') or ""
            if href:
                full = href if href.startswith("http") else "https://www.exploit-db.com" + href
                results.append({"title": title, "url": full})
        # dedupe
        uniq: List[Dict[str, str]] = []
        seen = set()
        for r_ in results:
            if r_["url"] not in seen:
                seen.add(r_["url"]); uniq.append(r_)
        return uniq
    except Exception:
        return []

def cve_fallbacks(cve: str) -> List[Dict[str, str]]:
    gh = f"https://github.com/search?q={requests.utils.quote(cve + ' exploit') if requests else cve + ' exploit'}"
    return [
        {"source": "NVD", "url": f"https://nvd.nist.gov/vuln/detail/{cve}"},
        {"source": "CVE.org", "url": f"https://www.cve.org/CVERecord?id={cve}"},
        {"source": "GitHub search", "url": gh}
    ]

# -------------------------
# LLaMA prompt builder & JSON extractor (keep original build_llm_prompt)
# -------------------------
JSON_MARKER = "### JSON OUTPUT ###"

def build_llm_prompt(detected: Dict[str, Any], recon_excerpt: str, mode: str="HYBRID") -> str:
    ev_lines = []
    for k, v in list(detected.get('source_lines', {}).items())[:40]:
        for ln in v[:2]:
            ev_lines.append(f"({k}) {ln}")
    ev_text = "\n".join(ev_lines) if ev_lines else "(no extracted source lines)"

    # Include CVE & vulnerability categories in the prompt
    cve_list = detected.get('cves', [])
    vuln_categories = [k for k, v in detected.items() if isinstance(v, list) or isinstance(v, str)]
    schema = {
        "summary": "string",
        "findings": [
            {"id": "string", "title": "string", "evidence": ["string"], "risk": "High|Medium|Low",
             "confidence": "0-100", "remediation": ["step1","step2","step3"], "hardening": ["step1","step2","step3"], "verification": ["string"]}
        ],
        "overall_risk": "High|Medium|Low",
        "recommended_actions": ["string"],
        "metadata": {"mode": mode}
    }
    prompt = (
        "You are a defensive cybersecurity analyst. NEVER provide exploit code, PoC payloads, or offensive step-by-step exploitation. "
        "Each finding MUST include 3 remediation steps and 3 hardening steps. Provide fewer or more.\n\n"
        f"MODE: {mode}\n"
        f"DETECTED CVES: {', '.join(cve_list) if cve_list else 'None'}\n"
        f"VULNERABILITY CATEGORIES DETECTED: {', '.join(vuln_categories)}\n\n"
        "TASK: Using the detected static-feature summary and the recon excerpt, produce:\n"
        "  1) A concise HUMAN-READABLE REPORT with numbered findings. Each finding MUST include quoted evidence lines, a single risk level (High/Medium/Low), and short step-by-step remediation steps and hardening checklist. "
        "Incorporate CVE info and vulnerability categories when suggesting remediation.\n"
        "  2) After the human report, on a new line output the exact marker '" + JSON_MARKER + "' and then ONLY a valid JSON object that follows the schema above. The JSON must be parsable and contain a 'findings' array.\n\n"
        f"SCHEMA EXAMPLE: {json.dumps(schema)}\n\n"
        "--- EXTRACTED SOURCE LINES (top) ---\n"
        f"{ev_text}\n"
        "--- END SOURCE LINES ---\n\n"
        "--- RECON EXCERPT (truncated) ---\n"
        f"{recon_excerpt[:8000]}\n"
        "--- END EXCERPT ---\n\n"
        "Be concrete, short steps, avoid hallucination. Use inert verification tokens (e.g., VERIFY-TOKEN-12345) where needed."
    )
    return prompt

def extract_json_after_marker(text: str, marker: str=JSON_MARKER):
    if not isinstance(text, str):
        return None
    idx = text.find(marker)
    if idx == -1:
        return None
    json_part = text[idx + len(marker):].strip()
    json_part = json_part.strip().lstrip('`').rstrip('`').strip()
    first = json_part.find('{')
    if first == -1:
        return None
    candidate = json_part[first:]
    stack = []
    end = None
    for i, ch in enumerate(candidate):
        if ch == '{':
            stack.append('{')
        elif ch == '}':
            if stack:
                stack.pop()
                if not stack:
                    end = i
                    break
    if end is None:
        try:
            return json.loads(candidate)
        except Exception:
            return None
    json_text = candidate[:end+1]
    try:
        return json.loads(json_text)
    except Exception:
        san = re.sub(r',\s*}', '}', json_text)
        san = re.sub(r',\s*]', ']', san)
        try:
            return json.loads(san)
        except Exception:
            return None

# -------------------------
# Next-steps prompt and marker
# -------------------------
NEXT_STEPS_MARKER = "### NEXT STEPS JSON ###"

def build_next_steps_prompt(detected: dict, recon_excerpt: str) -> str:
    """
    Build a LLaMA prompt to produce actionable next steps for the security team.
    Returns a prompt string.
    """
    cves = ", ".join(detected.get('cves', [])) or "None"
    techs = ", ".join(detected.get('tech_stack_detected', [])) or "None"
    # issues: summary of truthy keys excluding large structures
    issues = [k for k, v in detected.items() if v and k not in ('source_lines', 'cves')]
    prompt = (
        "You are a defensive cybersecurity analyst. DO NOT provide offensive steps, "
        "exploit code, or PoCs. Instead, produce actionable, professional, prioritized "
        "Next Steps for the Security Team based on the following reconnaissance findings.\n\n"
        f"DETECTED CVES: {cves}\n"
        f"TECH STACK DETECTED: {techs}\n"
        f"ISSUES DETECTED: {', '.join(issues) if issues else 'None'}\n\n"
        "TASK: Provide Next Steps divided into three sections:\n"
        "1) Immediate Action (urgent)\n"
        "2) Short-Term Action (weeks)\n"
        "3) Long-Term Hardening (months)\n\n"
        "Use professional, concise, and readable format suitable for a security team. "
        f"After the human-readable text, output the exact marker '{NEXT_STEPS_MARKER}' "
        "followed by a JSON object with three keys: 'immediate', 'short_term', 'long_term', "
        "each containing a list of actionable steps.\n\n"
        "--- RECON EXCERPT (truncated) ---\n"
        f"{recon_excerpt[:3500]}\n"
        "--- END EXCERPT ---\n"
    )
    return prompt

def extract_json_after_marker(text: str, marker: str = JSON_MARKER):
    """
    Extracts a JSON object that follows a marker in text.
    Handles trailing commas and attempts best-effort parsing.
    Returns the parsed JSON dict or None if parsing fails.
    """
    if not isinstance(text, str):
        return None

    idx = text.find(marker)
    if idx == -1:
        return None

    json_part = text[idx + len(marker):].strip()
    # remove backticks or code fences
    json_part = json_part.strip().lstrip('`').rstrip('`').strip()

    # find the first { ... } block
    first_brace = json_part.find('{')
    if first_brace == -1:
        return None

    candidate = json_part[first_brace:]
    stack = []
    end_idx = None
    for i, ch in enumerate(candidate):
        if ch == '{':
            stack.append('{')
        elif ch == '}':
            if stack:
                stack.pop()
                if not stack:
                    end_idx = i
                    break

    if end_idx is None:
        return None

    json_text = candidate[:end_idx + 1]

    # sanitize trailing commas
    json_text = re.sub(r',\s*}', '}', json_text)
    json_text = re.sub(r',\s*]', ']', json_text)

    try:
        return json.loads(json_text)
    except json.JSONDecodeError:
        return None


# -------------------------
# LLaMA invocation helper (robust)
# -------------------------
def call_llama(prompt: str, hf_token: str, model: str = LLaMA_MODEL, temperature: float = 0.0, max_tokens: int = 3500, retries: int = 2) -> str:
    """Call Hugging Face InferenceClient chat_completion for meta-llama model.
    Compatible with different versions of huggingface_hub.
    Clears common proxy env vars (Windows) to avoid connection issues.
    Returns raw model output or a descriptive error string.
    """
    if InferenceClient is None:
        return "ERROR: huggingface_hub not installed."

    # clear potentially problematic proxy env vars (user asked for this)
    os.environ.pop("HTTP_PROXY", None)
    os.environ.pop("http_proxy", None)
    os.environ.pop("HTTPS_PROXY", None)
    os.environ.pop("https_proxy", None)
    os.environ.pop("ALL_PROXY", None)
    os.environ.pop("all_proxy", None)

    attempt = 0
    while attempt <= retries:
        attempt += 1
        try:
            client = InferenceClient(token=hf_token)

            # prefer chat_completion
            if hasattr(client, "chat_completion"):
                resp = client.chat_completion(
                    model=model,
                    messages=[{"role": "user", "content": prompt}],
                    max_tokens=max_tokens,
                    temperature=temperature
                )
                # Try a few access patterns for response
                try:
                    # new-style: resp.choices[0].message.content or dict-access
                    if hasattr(resp, "choices"):
                        choice = resp.choices[0]
                        # two ways content may be stored
                        try:
                            return choice.message.content
                        except Exception:
                            try:
                                return choice.message["content"]
                            except Exception:
                                pass
                    # fallback to str
                    return str(resp)
                except Exception:
                    return str(resp)

            # fallback: text generation (older API)
            elif hasattr(client, "text_generation"):
                # text_generation often uses 'max_new_tokens'
                try:
                    gen = client.text_generation(prompt, max_new_tokens=max_tokens, temperature=temperature)
                    # gen may be list or dict
                    if isinstance(gen, list) and gen and isinstance(gen[0], dict):
                        return gen[0].get("generated_text", str(gen[0]))
                    if isinstance(gen, dict):
                        return gen.get("generated_text", str(gen))
                    return str(gen)
                except TypeError:
                    # maybe signature different
                    gen = client.text_generation(prompt)
                    return str(gen)
            else:
                return "ERROR: InferenceClient has neither chat_completion nor text_generation."

        except Exception as e:
            # If hf returns an HTTP error message with details, include body if available
            err_text = f"{e}"
            if attempt > retries:
                return f"LLM ERROR after {attempt} attempts: {err_text}\n{traceback.format_exc()}"
            # short backoff then retry
            time.sleep(1.5)
    return "LLM ERROR: exhausted retries"

# -------------------------
# Streamlit UI & main flow
# -------------------------
# Streamlit UI setup
st.set_page_config(page_title="Defensive Recon + LLaMA", layout="wide")
st.title("🔒 Defensive Recon + LLaMA (Defensive-only)")

col_main, col_side = st.columns([3, 1])

with col_side:
    st.header("Settings")
    use_embedded = st.checkbox("Use embedded HF token (in-code)", value=True)
    hf_token = HF_TOKEN_EMBEDDED if use_embedded else st.text_input("Hugging Face token", type="password")

    st.markdown("---")
    st.subheader("Model & LLM options")
    st.write(f"Model: `{LLaMA_MODEL}`")

    st.markdown("**Full report settings**")
    run_llm_full = st.checkbox("Run Full LLaMA report", value=True)
    full_temp = st.selectbox("Full report temperature", options=[0.0, 0.2, 0.5, 0.7], index=0)

    st.markdown("**Next Steps settings**")
    run_next_steps = st.checkbox("Run Next Steps", value=True)
    next_temp = st.selectbox("Next Steps temperature", options=[0.0, 0.3, 0.5, 0.7], index=2)

with col_main:
    uploaded = st.file_uploader("Upload reconnaissance TXT file", type=["txt"], accept_multiple_files=False)
    if uploaded:
        recon_text = uploaded.read().decode("utf-8", errors="ignore")
    else:
        recon_text = None

if not recon_text:
    st.info("Upload a reconnaissance TXT file to begin analysis.")
    st.stop()

# ---------- Static detection ----------
detected = dict(FEATURES)
detected['cves'] = set()
detected['source_lines'] = {}

for key, rx in PATTERNS.items():
    try:
        lines = find_source_lines(recon_text, rx)
    except Exception:
        lines = [ln for ln in recon_text.splitlines() if rx.search(ln)]
    if lines:
        detected['source_lines'][key] = lines
        if key == 'cve':
            found = set(re.findall(r'\bCVE-\d{4}-\d{4,7}\b', "\n".join(lines), re.IGNORECASE))
            detected['cves'].update([c.upper() for c in found])
        else:
            detected[key] = lines
        if key in ('aws_key', 'gcp_key', 'jwt', 'basic_auth', 'default_creds'):
            detected['has_sensitive_tokens'] = True
            if key in ('aws_key', 'gcp_key'):
                detected['aws_or_gcp_keys_exposed'] = True
        if key == 'framework_debug':
            detected['debug_mode_enabled'] = True
        if key in ('exposed_paths', 'sensitive_files'):
            detected['exposed_config_files'] = True

# tech/cdn detection
techs = [name for name, pat in TECH_PATTERNS.items() if re.search(pat, recon_text, re.I)]
if techs:
    detected['tech_stack_detected'] = techs
cdns = [name for name, pat in CDN_PATTERNS.items() if re.search(pat, recon_text, re.I)]
if cdns:
    detected['cdn_usage_detected'] = True
    detected['cdn_detected'] = cdns

# ports
port_matches = PATTERNS['open_ports'].findall(recon_text)
if port_matches:
    detected['open_ports_count'] = len(port_matches)
    detected['open_ports'] = [m[0] for m in port_matches]
    detected['has_http_port_open'] = any(p.startswith('80') for p in detected['open_ports'])
    detected['has_https_port_open'] = any(p.startswith('443') for p in detected['open_ports'])

# tls
tls = PATTERNS['tls_versions'].findall(recon_text)
if tls:
    detected['tls_versions_supported'] = tls
    detected['has_weak_tls'] = any(v in ('TLSv1.0','TLSv1.1') for v in tls)

# robots / directory / git
if re.search(r'/robots\.txt|/sitemap\.xml', recon_text, re.I):
    detected['robots_or_sitemap_found'] = True
if re.search(r'Index of /', recon_text, re.I):
    detected['directory_listing_enabled'] = True
if re.search(r'\.git/', recon_text, re.I):
    detected['git_or_repo_leak'] = True

# finalize CVE list
if isinstance(detected.get('cves'), set):
    detected['cves'] = sorted(list(detected['cves']))

# ---------- CVE -> ExploitDB/fallback ----------
cve_map: Dict[str, Any] = {}
for c in detected.get('cves', []) or []:
    ex = search_exploitdb(c) if (requests and BeautifulSoup) else []
    cve_map[c] = {'exploitdb': ex or [], 'fallbacks': cve_fallbacks(c)}

# ---------- LLaMA remediation (Full report) ----------
llm_out_full = "(not run)"
parsed_full = None

# prepare truncated excerpt once
lines = recon_text.splitlines()
excerpt_lines = lines[-200:] if len(lines) > 200 else lines
excerpt_text = "\n".join(excerpt_lines)
if len(excerpt_text) > 3500:
    excerpt_text = excerpt_text[-3500:]

if run_llm_full:
    if not hf_token:
        llm_out_full = "(LLM disabled: no HF token provided)"
    else:
        prompt_full = build_llm_prompt(detected, excerpt_text, mode="HYBRID")
        with st.spinner(f"Calling LLaMA Full Report (temp={full_temp})..."):
            llm_out_full = call_llama(prompt_full, hf_token, model=LLaMA_MODEL, temperature=float(full_temp), max_tokens=3500)
            parsed_full = extract_json_after_marker(llm_out_full)

# ---------- Next Steps generation ----------
next_steps_out = "(not run)"
next_steps_json = None

if run_next_steps:
    if not hf_token:
        next_steps_out = "(Next Steps disabled: no HF token provided)"
    else:
        prompt_next = build_next_steps_prompt(detected, excerpt_text)
        with st.spinner(f"Calling LLaMA Next Steps (temp={next_temp})..."):
            next_steps_out = call_llama(prompt_next, hf_token, model=LLaMA_MODEL, temperature=float(next_temp), max_tokens=3500)
            next_steps_json = extract_json_after_marker(next_steps_out, marker=NEXT_STEPS_MARKER)

# ---------- Streamlit Dashboard ----------
st.sidebar.header("Summary")
st.sidebar.metric("CVEs found", len(detected.get('cves', [])))
st.sidebar.metric("Open ports", detected.get('open_ports_count', 0))
st.sidebar.metric("Tech stacks", len(detected.get('tech_stack_detected', [])))
st.sidebar.write("Sensitive tokens:", "Yes" if detected.get('has_sensitive_tokens') else "No")
st.sidebar.write("Debug mode:", "Yes" if detected.get('debug_mode_enabled') else "No")
st.sidebar.markdown("---")
st.sidebar.write("Model:", LLaMA_MODEL)

st.header("Detections & Source Lines")

def show_popup(title: str, content: str):
    """Display a scrollable popup using Streamlit modal pattern."""
    with st.expander(f"View {title}", expanded=False):
        st.code(content, language=None, line_numbers=False)

if detected.get('source_lines'):
    for key, lines in detected['source_lines'].items():
        show_popup(f"{key} ({len(lines)} lines)", "\n".join(lines))

st.header("CVE / Exploit-DB / Fallback Links")
if detected.get('cves'):
    for cve, info in cve_map.items():
        with st.expander(cve, expanded=False):
            if info['exploitdb']:
                st.markdown("**Exploit-DB results (best-effort):**")
                for hit in info['exploitdb']:
                    st.markdown(f"- [{hit.get('title','exploit')}]({hit.get('url')})")
            st.markdown("**Fallback links:**")
            for fb in info['fallbacks']:
                st.markdown(f"- [{fb['source']}]({fb['url']})")
else:
    st.info("No CVEs detected.")

st.header("LLaMA Report / Next Steps")
if run_llm_full:
    show_popup("Full Report", llm_out_full)
if run_next_steps:
    show_popup("Next Steps", next_steps_out)

def format_results_human_readable(detected, cve_map, llm_full, next_steps):
    lines = []

    lines.append("=== DETECTIONS SUMMARY ===\n")
    lines.append(f"CVEs found: {len(detected.get('cves', []))}")
    lines.append(f"Open ports: {detected.get('open_ports_count', 0)}")
    lines.append(f"Tech stacks: {', '.join(detected.get('tech_stack_detected', [])) or 'None'}")
    lines.append(f"Sensitive tokens: {'Yes' if detected.get('has_sensitive_tokens') else 'No'}")
    lines.append(f"Debug mode: {'Yes' if detected.get('debug_mode_enabled') else 'No'}")
    lines.append("")

    lines.append("=== SOURCE LINES DETECTED ===")
    for key, vals in detected.get('source_lines', {}).items():
        lines.append(f"\n[{key}] ({len(vals)} lines)")
        for ln in vals[:5]:  # show top 5 lines for readability
            lines.append(f"  {ln}")
        if len(vals) > 5:
            lines.append(f"  ... ({len(vals)-5} more lines)")

    lines.append("\n=== CVE / EXPLOIT LINKS ===")
    for cve, info in cve_map.items():
        lines.append(f"\n{cve}:")
        if info['exploitdb']:
            lines.append("  Exploit-DB:")
            for e in info['exploitdb']:
                lines.append(f"    - {e['title']}: {e['url']}")
        lines.append("  Fallbacks:")
        for fb in info['fallbacks']:
            lines.append(f"    - {fb['source']}: {fb['url']}")

    lines.append("\n=== LLaMA FULL REPORT ===\n")
    lines.append(llm_full[:10000] + ('...' if len(llm_full) > 10000 else ''))

    lines.append("\n=== NEXT STEPS REPORT ===\n")
    lines.append(next_steps[:10000] + ('...' if len(next_steps) > 10000 else ''))

    return "\n".join(lines)

# ---------- Download all results ----------
all_results = {
    "detections": detected,
    "cve_map": cve_map,
    "llm_full_report": llm_out_full,
    "next_steps_report": next_steps_out
}
all_results_txt = format_results_human_readable(detected, cve_map, llm_out_full, next_steps_out)

st.download_button(
    label="Download Professional Results (.txt)",
    data=all_results_txt,
    file_name=(uploaded.name.split('.')[0] if uploaded else "recon") + "_all_results.txt",
    mime="text/plain"
)

st.caption("Defensive-only tool. Only analyze targets you own or are authorized to test.")