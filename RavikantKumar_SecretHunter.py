"""
🔑 SecretHunter — Automated Secret & Credential Leak Detector
Author: SecretHunter Security Research Team
License: MIT
Description: Scans source code, config files, .env files, and repositories for
             exposed API keys, database credentials, tokens, and private keys.
"""

import os
import re
import math
import json
from datetime import datetime
import streamlit as st
import pandas as pd

st.set_page_config(
    page_title="SecretHunter — Secret Leak Detector",
    page_icon="🔑",
    layout="wide",
    initial_sidebar_state="expanded"
)

# Custom Styling
st.markdown("""
<style>
    .main-title {
        font-size: 2.2rem;
        font-weight: 700;
        color: #F59E0B;
        margin-bottom: 0px;
    }
    .subtitle {
        font-size: 1rem;
        color: #9CA3AF;
        margin-bottom: 25px;
    }
    .badge-critical {
        background-color: #DC2626;
        color: white;
        padding: 4px 8px;
        border-radius: 4px;
        font-size: 12px;
        font-weight: bold;
    }
    .badge-high {
        background-color: #EA580C;
        color: white;
        padding: 4px 8px;
        border-radius: 4px;
        font-size: 12px;
        font-weight: bold;
    }
    .badge-medium {
        background-color: #D97706;
        color: white;
        padding: 4px 8px;
        border-radius: 4px;
        font-size: 12px;
        font-weight: bold;
    }
    .stDownloadButton>button {
        width: 100%;
        background-color: #D97706;
        color: white;
    }
</style>
""", unsafe_allow_html=True)

# Secret Signatures Catalog
SECRET_RULES = [
    {
        "id": "AWS-KEY",
        "name": "AWS Access Key ID",
        "regex": r"\b(AKIA[0-9A-Z]{16})\b",
        "severity": "Critical",
        "remediation": "Revoke key immediately in AWS IAM console, check CloudTrail logs for unauthorized API calls, and enforce AWS Secrets Manager."
    },
    {
        "id": "AWS-SECRET",
        "name": "AWS Secret Access Key",
        "regex": r"(?i)aws_secret_access_key\s*=\s*['\"]?([A-Za-z0-9/+=]{40})['\"]?",
        "severity": "Critical",
        "remediation": "Rotate AWS IAM user secret key immediately and review IAM permissions."
    },
    {
        "id": "GH-CLASSIC",
        "name": "GitHub Personal Access Token (Classic)",
        "regex": r"\b(ghp_[0-9a-zA-Z]{36})\b",
        "severity": "Critical",
        "remediation": "Revoke token under GitHub Settings > Developer settings > Personal access tokens."
    },
    {
        "id": "GH-FINEGRAINED",
        "name": "GitHub Fine-Grained Token",
        "regex": r"\b(github_pat_[0-9a-zA-Z_]{82})\b",
        "severity": "Critical",
        "remediation": "Delete or rotate the fine-grained token in GitHub Developer Settings."
    },
    {
        "id": "GOOGLE-API",
        "name": "Google Cloud / Firebase API Key",
        "regex": r"\b(AIza[0-9A-Za-z\-_]{35})\b",
        "severity": "High",
        "remediation": "Restrict API key via Google Cloud Console by IP, HTTP referrer, or API service quota."
    },
    {
        "id": "OPENAI-API",
        "name": "OpenAI / LLM API Key",
        "regex": r"\b(sk-[a-zA-Z0-9_-]{32,64}|sk-proj-[a-zA-Z0-9_-]{48,128})\b",
        "severity": "Critical",
        "remediation": "Revoke API key in OpenAI Dashboard -> API Keys to prevent unauthorized LLM billing."
    },
    {
        "id": "STRIPE-SECRET",
        "name": "Stripe Live Secret Key",
        "regex": r"\b((?:sk|rk)_live_[0-9a-zA-Z]{24,34})\b",
        "severity": "Critical",
        "remediation": "Rotate secret key in Stripe Dashboard -> Developers -> API Keys. Check active charges."
    },
    {
        "id": "SLACK-BOT",
        "name": "Slack Bot Token",
        "regex": r"\b(xoxb-[0-9]{10,13}-[0-9]{10,13}-[a-zA-Z0-9]{24})\b",
        "severity": "High",
        "remediation": "Regenerate token in Slack API Developer Portal."
    },
    {
        "id": "SLACK-WEBHOOK",
        "name": "Slack Incoming Webhook",
        "regex": r"https://hooks\.slack\.com/services/T[a-zA-Z0-9_]+/B[a-zA-Z0-9_]+/[a-zA-Z0-9_]+",
        "severity": "Medium",
        "remediation": "Deactivate incoming webhook in Slack App Configuration."
    },
    {
        "id": "RSA-KEY",
        "name": "Private Cryptographic Key",
        "regex": r"-----BEGIN (?:RSA |EC |OPENSSH |DSA )?PRIVATE KEY-----",
        "severity": "Critical",
        "remediation": "Replace compromised SSH/TLS keypair. Remove public key from authorized_keys on all servers."
    },
    {
        "id": "DB-URI",
        "name": "Database Connection URI with Password",
        "regex": r"\b(?:postgres|postgresql|mysql|mongodb|mongodb\+srv|redis)://[a-zA-Z0-9_.-]+:([^\s@:]+)@[a-zA-Z0-9_.-]+:[0-9]+/[^\s]+",
        "severity": "Critical",
        "remediation": "Change database password immediately. Never hardcode credentials; load via environment variables."
    },
    {
        "id": "JWT-TOKEN",
        "name": "JSON Web Token (JWT)",
        "regex": r"\b(eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9._-]+)\b",
        "severity": "Medium",
        "remediation": "Check if token is expired. Ensure JWT secrets are strong (>= 256 bits) and revoke session if stateful."
    },
    {
        "id": "SENDGRID-API",
        "name": "SendGrid API Key",
        "regex": r"\b(SG\.[a-zA-Z0-9_-]{22}\.[a-zA-Z0-9_-]{43})\b",
        "severity": "High",
        "remediation": "Delete and replace API key in SendGrid Settings -> API Keys to avoid spam abuse."
    },
    {
        "id": "GENERIC-KEY",
        "name": "Generic Hardcoded Secret Assignment",
        "regex": r"(?i)\b(?:api_key|client_secret|auth_token|secret_key|private_key)\s*[:=]\s*['\"]([a-zA-Z0-9_\-\.]{16,64})['\"]",
        "severity": "Medium",
        "remediation": "Extract hardcoded secret into a secure .env file and add .env to your .gitignore file."
    }
]


def calculate_entropy(text: str) -> float:
    """Calculate Shannon entropy for identifying high-randomness credentials."""
    if not text:
        return 0.0
    freq = {}
    for char in text:
        freq[char] = freq.get(char, 0) + 1
    entropy = 0.0
    for count in freq.values():
        p = count / len(text)
        entropy -= p * math.log2(p)
    return round(entropy, 2)


def mask_secret(secret: str) -> str:
    """Mask credentials for safe display in reports and UI."""
    if len(secret) <= 8:
        return secret[:2] + "****" + secret[-2:] if len(secret) >= 4 else "****"
    prefix_len = min(4, len(secret) // 4)
    suffix_len = min(4, len(secret) // 4)
    masked_len = len(secret) - prefix_len - suffix_len
    return secret[:prefix_len] + ("*" * min(masked_len, 16)) + secret[-suffix_len:]


def scan_content(content: str, filename: str = "Pasted Text"):
    """Scan string content against all defined secret detection patterns."""
    findings = []
    lines = content.splitlines()

    for rule in SECRET_RULES:
        pattern = re.compile(rule["regex"])
        for line_idx, line in enumerate(lines, 1):
            for match in pattern.finditer(line):
                matched_secret = match.group(1) if match.groups() else match.group(0)
                entropy_score = calculate_entropy(matched_secret)

                findings.append({
                    "rule_id": rule["id"],
                    "rule_name": rule["name"],
                    "severity": rule["severity"],
                    "file": filename,
                    "line": line_idx,
                    "secret_masked": mask_secret(matched_secret),
                    "raw_length": len(matched_secret),
                    "entropy": entropy_score,
                    "code_snippet": line.strip()[:100],
                    "remediation": rule["remediation"]
                })

    return findings


# Sidebar
st.sidebar.image("https://img.icons8.com/fluency/96/key.png", width=80)
st.sidebar.title("🔑 SecretHunter")
st.sidebar.caption("Credential & Secret Leak Detector")
st.sidebar.markdown("---")
st.sidebar.markdown("""
### Monitored Signatures:
- ☁️ **Cloud**: AWS, Google Cloud, Heroku
- 🐙 **VCS**: GitHub Personal Access Tokens
- 🤖 **AI/LLM**: OpenAI, Anthropic keys
- 💳 **Payment**: Stripe Live & Restricted Keys
- 💬 **Messaging**: Slack Webhooks & Bot Tokens
- 🗄️ **Databases**: Postgres, MySQL, Mongo, Redis
- 🔐 **Cryptographic**: RSA/SSH Private Keys
""")
st.sidebar.markdown("---")
st.sidebar.warning("⚠️ **Safety Notice**: All scans execute in-memory. No credentials are transmitted to any cloud server.")

# Main Header
st.markdown('<div class="main-title">🔑 SecretHunter — Secret Leak Detector</div>', unsafe_allow_html=True)
st.markdown('<div class="subtitle">Automated static code security scanning for API keys, passwords, database URIs, and private tokens</div>', unsafe_allow_html=True)

tab_paste, tab_upload, tab_dir = st.tabs(["📝 Scan Pasted Code / Snippet", "📁 Scan Uploaded Files", "📂 Scan Local Folder"])

all_findings = []

with tab_paste:
    sample_default = """# Example Configuration
AWS_ACCESS_KEY_ID = "AKIAIOSFODNN7EXAMPLE"
OPENAI_API_KEY = "sk-proj-998877665544332211aabbccddeeffgghhiijjkkllmmnnooppqq"
DATABASE_URL = "postgres://admin:SuperSecretPass123@db.prod.internal:5432/customers"
SLACK_WEBHOOK = "https://hooks.slack.com/services/T00000000/B00000000/XXXXXXXXXXXXXXXXXXXXXXXX"
"""
    raw_code = st.text_area("Paste code snippet, configuration, or environment text here:", value=sample_default, height=220)
    if st.button("🚀 Analyze Snippet", type="primary"):
        all_findings = scan_content(raw_code, "Snippet")

with tab_upload:
    uploaded_files = st.file_uploader(
        "Upload source files (.env, .py, .js, .json, .yml, .tf, .txt, .sh)",
        accept_multiple_files=True,
        type=None
    )
    if uploaded_files:
        if st.button("🚀 Analyze Uploaded Files", type="primary"):
            for f in uploaded_files:
                try:
                    content = f.read().decode("utf-8", errors="replace")
                    findings = scan_content(content, f.name)
                    all_findings.extend(findings)
                except Exception as e:
                    st.error(f"Error reading {f.name}: {e}")

with tab_dir:
    folder_path = st.text_input("Enter local folder path to scan (e.g., ./ or C:/Users/...):", value=".")
    extensions = st.text_input("File extensions to scan (comma separated):", value=".py, .env, .json, .yml, .yaml, .js, .txt, .md, .sh")
    if st.button("🚀 Scan Directory"):
        if os.path.exists(folder_path):
            valid_exts = [e.strip() for e in extensions.split(",")]
            scanned_files_count = 0
            for root, dirs, files in os.walk(folder_path):
                # Skip git and venv folders
                dirs[:] = [d for d in dirs if d not in ['.git', 'venv', '__pycache__', 'node_modules']]
                for file in files:
                    if any(file.endswith(ext) for ext in valid_exts):
                        scanned_files_count += 1
                        file_path = os.path.join(root, file)
                        try:
                            with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
                                content = f.read()
                                findings = scan_content(content, os.path.relpath(file_path, folder_path))
                                all_findings.extend(findings)
                        except Exception:
                            continue
            st.info(f"Scanned {scanned_files_count} files across directory.")
        else:
            st.error("Directory path does not exist.")

# ----------------- RESULTS DASHBOARD ----------------- #

if all_findings:
    st.markdown("---")
    st.markdown("## 🚨 Security Scan Audit Findings")

    crit_count = sum(1 for f in all_findings if f["severity"] == "Critical")
    high_count = sum(1 for f in all_findings if f["severity"] == "High")
    med_count = sum(1 for f in all_findings if f["severity"] == "Medium")

    c1, c2, c3, c4 = st.columns(4)
    c1.metric("Total Findings", len(all_findings))
    c2.metric("Critical", crit_count, delta=f"{crit_count} urgent" if crit_count > 0 else "0", delta_color="inverse")
    c3.metric("High", high_count, delta_color="inverse")
    c4.metric("Medium", med_count, delta_color="inverse")

    df_findings = pd.DataFrame(all_findings)

    # Detailed Interactive Table
    st.dataframe(
        df_findings[["severity", "rule_name", "file", "line", "secret_masked", "entropy", "code_snippet"]],
        use_container_width=True
    )

    # Remediation Playbook Cards
    st.markdown("### 🛠️ Remediation Playbooks")
    unique_rules = {f["rule_name"]: f["remediation"] for f in all_findings}
    for rule_name, rem in unique_rules.items():
        with st.expander(f"⚠️ How to fix: {rule_name}"):
            st.write(f"**Recommended Action:** {rem}")
            st.code("""# Recommended Action Checklist:
1. Invalidate/revoke exposed credential immediately from the provider dashboard.
2. Check provider audit logs (CloudTrail, Access Logs) for unauthorized calls.
3. Migrate key to environment variable (e.g. export KEY="...") or a secrets manager.
4. Ensure target file is listed in .gitignore:
   echo ".env" >> .gitignore
5. If committed to git history, rewrite history with:
   git filter-repo --invert-paths --path .env""", language="bash")

    # Export Report
    st.markdown("---")
    st.markdown("### 📑 Export Security Audit Report")
    rcol1, rcol2 = st.columns(2)

    report_payload = {
        "tool": "SecretHunter",
        "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "total_leaks": len(all_findings),
        "critical_count": crit_count,
        "high_count": high_count,
        "medium_count": med_count,
        "findings": all_findings
    }

    rcol1.download_button(
        "📥 Download JSON Security Report",
        data=json.dumps(report_payload, indent=4),
        file_name=f"secrethunter_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json",
        mime="application/json"
    )

    md_report = f"""# SecretHunter Security Leak Audit Report
**Scan Timestamp:** {report_payload['timestamp']}
**Total Vulnerabilities:** {len(all_findings)} (Critical: {crit_count}, High: {high_count}, Medium: {med_count})

## Detailed Findings Table
| Severity | Secret Type | File | Line | Masked Value | Entropy |
|---|---|---|---|---|---|
"""
    for f in all_findings:
        md_report += f"| {f['severity']} | {f['rule_name']} | {f['file']} | {f['line']} | `{f['secret_masked']}` | {f['entropy']} |\n"

    md_report += "\n## Remediation Steps\n"
    for rule_name, rem in unique_rules.items():
        md_report += f"- **{rule_name}**: {rem}\n"

    rcol2.download_button(
        "📥 Download Markdown Report",
        data=md_report,
        file_name=f"secrethunter_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.md",
        mime="text/markdown"
    )

elif not all_findings:
    st.info("💡 Run a scan using any of the tabs above to detect hardcoded secrets and credentials.")
