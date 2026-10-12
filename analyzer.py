import requests

class SecurityAnalyzer:
    """Analyzes HTTP response headers for security best practices."""

    # Configuration for security headers: (Ideal value/condition, description)
    HEADER_RULES = {
        "Content-Security-Policy": {
            "description": "Prevents Cross-Site Scripting (XSS) and data injection attacks.",
            "check": lambda val: val is not None and "unsafe-inline" not in val.lower(),
            "recommendation": "Implement a strict CSP that avoids 'unsafe-inline' and 'unsafe-eval'."
        },
        "Strict-Transport-Security": {
            "description": "Forces the browser to use HTTPS for all future requests.",
            "check": lambda val: val is not None and "max-age=" in val.lower(),
            "recommendation": "Enable HSTS with a long max-age (e.g., 31536000 seconds)."
        },
        "X-Frame-Options": {
            "description": "Prevents Clickjacking by restricting if the site can be embedded in frames.",
            "check": lambda val: val is not None and val.upper() in ["DENY", "SAMEORIGIN"],
            "recommendation": "Set X-Frame-Options to 'DENY' or 'SAMEORIGIN'."
        },
        "X-Content-Type-Options": {
            "description": "Prevents the browser from MIME-sniffing a response away from the declared content-type.",
            "check": lambda val: val is not None and val.lower() == "nosniff",
            "recommendation": "Set X-Content-Type-Options to 'nosniff'."
        },
        "Referrer-Policy": {
            "description": "Controls how much referrer information is included with requests.",
            "check": lambda val: val is not None and val.lower() in ["no-referrer", "strict-origin-when-cross-origin", "same-origin"],
            "recommendation": "Set a restrictive Referrer-Policy like 'no-referrer' or 'strict-origin-when-cross-origin'."
        },
        "Permissions-Policy": {
            "description": "Controls which browser features are allowed to be used (e.g., camera, microphone).",
            "check": lambda val: val is not None,
            "recommendation": "Define a Permissions-Policy to restrict access to sensitive browser APIs."
        }
    }

    def __init__(self, url):
        self.url = url
        self.headers = {}
        self.results = {}
        self.score = 0

    def fetch_headers(self):
        """Fetches headers from the target URL."""
        try:
            # Use a generic User-Agent to avoid being blocked by some sites
            headers = {'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36'}
            response = requests.get(self.url, headers=headers, timeout=10, allow_redirects=True)
            self.headers = response.headers
            return True
        except requests.exceptions.RequestException as e:
            print(f"Error fetching headers: {e}")
            return False

    def analyze(self):
        """Analyzes the fetched headers against the rules."""
        if not self.headers:
            return None

        total_checks = len(self.HEADER_RULES)
        passed_checks = 0

        for header, rule in self.HEADER_RULES.items():
            value = self.headers.get(header)
            is_secure = rule["check"](value)

            self.results[header] = {
                "value": value,
                "secure": is_secure,
                "description": rule["description"],
                "recommendation": rule["recommendation"] if not is_secure else "Correctly configured."
            }

            if is_secure:
                passed_checks += 1

        self.score = int((passed_checks / total_checks) * 100)
        return self.results, self.score
