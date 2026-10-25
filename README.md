# Email Verifier Extension

A privacy-focused, 100% free browser Extension (Manifest V3) that inspects sender authenticity, detects lookalike and typosquatting domains, evaluates authentication and header alignment, analyzes suspicious URLs and attachments, provides academic protection mode, and generates explainable risk assessments directly inside Gmail.

---

## Key Features

### 1. Sender Identity & Lookalike-Domain Detection
- **Punycode & Unicode Confusable (Homoglyph) Detection**: Identifies visually deceptive characters (Cyrillic, Greek lookalikes such as `а`, `р`, `о` mimicking Latin letters).
- **Typosquatting & Edit-Distance Checks**: Flags character substitutions (e.g., `0` for `o`, `rn` for `m`, `1` for `l`), insertions, deletions, transpositions, and repeated letters against high-profile targets.
- **Deceptive Subdomain Detection**: Warns when trusted brand names are embedded inside unrelated root domains (e.g., `paypal.com.account-update.xyz`).
- **Free-Email Impersonation**: Detects when official, corporate, or banking titles appear in the display name while sending from generic public webmail providers.
- **Reply-To Mismatch Analysis**: Highlights when replies will be redirected to an unrelated domain or personal webmail address.

### 2. Email Authentication & Header Alignment
- **Infrastructure Alignment**: Evaluates Gmail-rendered envelope metadata (`mailed-by:` for SPF alignment and `signed-by:` for DKIM alignment) against the sender's From domain.
- **Public DNS Policy Inspection**: Queries published SPF (`v=spf1 ...`) and DMARC (`_dmarc.<domain>`) TXT records via privacy-preserving Google Public DNS (DoH).
- **Honest Technical Labeling**: Clearly distinguishes between mail-infrastructure-reported results, DNS policy configurations, and checks that are not accessible within the standard reading view without opening "Show original".

### 3. Explainable Risk Assessment & Reporting
- **Clear Risk Categories**: `HIGH RISK`, `CAUTION`, and `NO MAJOR INDICATORS DETECTED`.
- **Deduplicated Evidence**: Aggregates all security signals with severity badges, plain-language explanations, and recommended actions without artificial score inflation.
- **Privacy-Conscious Reports**: 1-click generation of exportable text and JSON security assessments containing only domain and security findings (never full email bodies, attachments, or personal contacts).

### 4. Client-Side Suspicious Link & URL Inspection
- **Displayed Text Mismatch**: Detects links whose visible text shows a legitimate domain (e.g. `https://paypal.com`) while pointing to a different destination.
- **IP-Address URLs & Shorteners**: Flags raw numeric IP destinations and URL shortening services.
- **Dangerous Schemes & Auth Tricks**: Identifies `javascript:`, `data:`, embedded user credentials (`user@host`), and open redirect parameters (`?dest=...`).
- **Zero-Execution Safety**: URL analysis is strictly local and non-intrusive—never visits, executes, or submits data to links.

### 5. Attachment Risk Analysis
- **Misleading Double Extensions**: Flags deceptive filenames such as `invoice.pdf.exe` or `report.docx.vbs`.
- **Executables & Scripts**: Detects `.exe`, `.scr`, `.bat`, `.cmd`, `.ps1`, `.vbs`, `.js`, `.hta`, and `.msi`.
- **Macro-Enabled Documents**: Alerts for macro-bearing Office files (`.docm`, `.xlsm`, `.pptm`).
- **HTML Attachments**: Warns about attached web pages frequently used for offline credential phishing.

### 6. Academic Email Protection Mode
- Tailored for students, researchers, professors, and university applicants.
- **Faculty Impersonation Alerts**: Warns when display names claim professorial or university authority while sending from non-institutional accounts.
- **Predatory Publishing & Solicitations**: Detects unsolicited journal invitations promising rapid, guaranteed publication in exchange for author fees.
- **Academic Fee Scams**: Identifies unexpected demands for application, visa, or processing fees in fellowship or admissions contexts.
- **Institutional Domain Directory**: Allows users to manage official university domains (`.edu`, `.ac.uk`, `.edu.bd`, etc.).

### 7. Multilingual Support (English & Bangla)
- Full translation for all risk categories, warning labels, technical explanations, recommendations, and settings.
- Instant 1-click language switch in the popup header (`EN` / `বাংলা`).

### 8. Safe Senders & Sender History Management
- **Local Safe Database**: Preloaded with popular domains and supports custom additions with optional notes.
- **Sender Drift Detection**: Locally remembers familiar contacts and alerts if a known sender unexpectedly changes domains or Reply-To addresses.
- **Safe JSON Backup & Restore**: Full import/export capabilities with strict schema validation.

---

## Architecture & Privacy Guarantees

- **100% Free & Self-Contained**: No paid APIs, no API keys, no subscriptions, and no mandatory external servers.
- **Zero Content Transmission**: Email bodies, attachments, and personal contact lists are processed purely in local browser memory and never leave your machine.
- **Minimal Permissions**: Uses only `storage` and host permission for `https://dns.google/*` (free DNS-over-HTTPS).
- **Graceful Network Handling**: The extension remains fully functional when offline; DNS queries fail gracefully without blocking analysis.

---

## Installation &  Setup

1. Clone or download this repository:
   ```bash
   git clone https://github.com/sabbir-21/email-checker.git
   ```
2. Open browser and navigate to:
   ```
   chrome://extensions/
   ```
3. Enable **Developer mode** using the toggle switch in the top-right corner.
4. Click the **Load unpacked** button in the top-left corner.
5. Select the `email-checker` project directory.
6. Open [Gmail](https://mail.google.com/) and click on any email conversation.
   - The draggable verification widget will appear in the top-right corner showing the sender's security assessment.
   - Navigate back to the inbox or folder view and the widget automatically dismisses itself cleanly.

---

## Running Automated Tests

The repository includes a comprehensive, standalone test suite with zero npm dependencies:

```bash
node test/test-all.js
```

### Test Coverage
- **i18n**: Language toggles and parameter interpolation in English and Bangla.
- **Domain Utilities**: Email extraction, multi-part SLD root extraction, homoglyphs, Punycode, typosquatting (Damerau-Levenshtein & visual substitutions), deceptive subdomains, free-email impersonation, and Reply-To mismatch.
- **URL Analyzer**: IP URLs, dangerous schemes, shorteners, text mismatches, and redirect parameters.
- **Attachment Analyzer**: Executables, double extensions, macros, and HTML attachments.
- **Phishing Detector**: Social engineering, urgent payment, and credential requests in English & Bangla.
- **Academic Protection**: TLD detection, faculty impersonation, predatory journals, and fee scams.
- **Sender History**: Schema migration, observation tracking, drift detection, and JSON import validation.
- **Risk Engine**: Assessment scoring, evidence deduplication, and privacy-preserving report generation.

---

## Known Technical Limitations

1. **Gmail Reading Pane Headers**: Full raw RFC 822 MIME headers (such as raw `Received:` and raw `Authentication-Results:` strings) are received by Google's mail servers and rendered in Gmail's dropdown as `mailed-by:`, `signed-by:`, and security status. The extension evaluates these visible infrastructure-reported headers and queries published DNS records. Raw header analysis requires opening "Show original", which Gmail opens in a separate view tab.
2. **DNS-over-HTTPS Connectivity**: DNS checks require access to `https://dns.google/resolve`. If the user is offline or DNS is blocked by network firewalls, the extension gracefully labels DNS checks as unavailable and completes all local heuristic evaluations normally.

---

## Author

Developed by **Sabbir Ahmed**  
- [GitHub](https://github.com/sabbir-21)
- [Facebook](https://www.facebook.com/sabbir299)
