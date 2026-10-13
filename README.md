# 🛡️ Web Security Header Analyzer

A professional Python-based CLI tool that audits a website's HTTP response headers against industry security best practices. This tool helps developers and security researchers identify missing or misconfigured headers that could leave a site vulnerable to common attacks.

## 🚀 Features
- **Instant Audit:** Checks for 6 critical security headers.
- **Security Scoring:** Provides an overall security score (0-100%) based on configuration.
- **Actionable Advice:** Offers specific recommendations for every failed check.
- **Report Generation:** Outputs results to the terminal (with colors) and can export to a Markdown file.

## 🛠️ Security Headers Analyzed

| Header | Purpose | Mitigates Against |
| :--- | :--- | :--- |
| `Content-Security-Policy` | Controls which resources the browser is allowed to load. | Cross-Site Scripting (XSS), Data Injection |
| `Strict-Transport-Security` | Forces the browser to use HTTPS. | Man-in-the-Middle (MITM), SSL Stripping |
| `X-Frame-Options` | Controls whether a page can be rendered in a frame/iframe. | Clickjacking |
| `X-Content-Type-Options` | Stops the browser from guessing the MIME type. | MIME-sniffing attacks |
| `Referrer-Policy` | Controls how much referrer info is sent with requests. | Information Leakage |
| `Permissions-Policy` | Limits access to browser APIs (camera, mic, etc.). | Privacy Intrusion |

## 📦 Installation

### Prerequisites
- Python 3.10 or higher

### Setup
1. Clone the repository:
   ```bash
   git clone https://github.com/YOUR_USERNAME/web-security-analyzer.git
   cd web-security-analyzer
   ```

2. Install dependencies:
   ```bash
   pip install -r requirements.txt
   ```

## 💻 Usage

Run the analyzer by providing a URL:
```bash
python main.py https://google.com
```

To save the results to a report file:
```bash
python main.py https://google.com -o report.md
```

## 📊 Example Output
The tool provides a color-coded terminal output:
- ✅ **[PASS]**: Header is present and correctly configured.
- ❌ **[FAIL]**: Header is missing or poorly configured.

## 🛡️ Disclaimer
This tool is for educational and authorized security testing purposes only. Do not use it to scan websites you do not have explicit permission to test.

---

