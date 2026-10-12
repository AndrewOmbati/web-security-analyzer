import sys
import argparse
from analyzer import SecurityAnalyzer
from reports import print_terminal_report, save_markdown_report

def main():
    parser = argparse.ArgumentParser(description="Web Security Header Analyzer - Audit your site's security headers.")
    parser.add_argument("url", help="The URL of the website to analyze (e.g., https://google.com)")
    parser.add_argument("-o", "--output", help="Save the report to a file (e.g., report.md)", default=None)

    args = parser.parse_args()
    url = args.url

    # Ensure URL starts with http or https
    if not url.startswith(("http://", "https://")):
        url = "https://" + url

    print(f"Analyzing {url}...")

    analyzer = SecurityAnalyzer(url)
    if analyzer.fetch_headers():
        results, score = analyzer.analyze()

        # 1. Print to terminal
        print_terminal_report(url, score, results)

        # 2. Save to file if requested
        if args.output:
            save_markdown_report(url, score, results, args.output)
            print(f"\nReport saved to {args.output}")
    else:
        print("Failed to fetch headers. Please check the URL and try again.")
        sys.exit(1)

if __name__ == "__main__":
    main()
