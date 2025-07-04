#!/usr/bin/env python3
"""
PyWebScan - Advanced Web Vulnerability Scanner
Detects XSS and SQL Injection vulnerabilities with advanced crawling capabilities
"""

import argparse
import sys
import os
import json
from datetime import datetime
from core.crawler import WebCrawler
from core.scanner import VulnerabilityScanner
from core.report import ReportGenerator
from utils.logger import setup_logger
from utils.config import Config

def banner():
    """Display PyWebScan banner"""
    print("""
    ╔═══════════════════════════════════════════════════════════════╗
    ║                        PyWebScan v1.0                         ║
    ║                Advanced Web Security Scanner                  ║
    ║              XSS & SQL Injection Detection Tool               ║
    ╚═══════════════════════════════════════════════════════════════╝
    """)

def parse_arguments():
    """Parse command line arguments"""
    parser = argparse.ArgumentParser(
        description="PyWebScan - Advanced XSS & SQLi Vulnerability Scanner",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python main.py -u http://target.com
  python main.py -u http://target.com --depth 3 --threads 20
  python main.py -u http://target.com --output report.html --format html
  python main.py -u http://target.com --auth-cookie "session=abc123"
  python main.py -u http://target.com --proxy http://127.0.0.1:8080
        """
    )
    
    # Required arguments
    parser.add_argument(
        "-u", "--url", 
        required=True,
        help="Target URL to scan (e.g., http://example.com)"
    )
    
    # Optional arguments
    parser.add_argument(
        "--depth", 
        type=int, 
        default=2,
        help="Crawling depth (default: 2)"
    )
    
    parser.add_argument(
        "--threads", 
        type=int, 
        default=10,
        help="Number of threads for parallel scanning (default: 10)"
    )
    
    parser.add_argument(
        "--output", 
        help="Output file path (default: reports/scan_TIMESTAMP)"
    )
    
    parser.add_argument(
        "--format", 
        choices=['html', 'pdf', 'json'],
        default='html',
        help="Report format (default: html)"
    )
    
    parser.add_argument(
        "--payloads", 
        default="payloads/payloads.json",
        help="Custom payloads file path"
    )
    
    parser.add_argument(
        "--auth-cookie", 
        help="Authentication cookie for session-aware scanning"
    )
    
    parser.add_argument(
        "--proxy", 
        help="Proxy URL (e.g., http://127.0.0.1:8080)"
    )
    
    parser.add_argument(
        "--timeout", 
        type=int, 
        default=10,
        help="Request timeout in seconds (default: 10)"
    )
    
    parser.add_argument(
        "--user-agent", 
        default="PyWebScan/2.0",
        help="Custom User-Agent string"
    )
    
    parser.add_argument(
        "--verbose", "-v", 
        action="store_true",
        help="Enable verbose output"
    )
    
    parser.add_argument(
        "--no-crawl", 
        action="store_true",
        help="Skip crawling, scan only the provided URL"
    )
    
    parser.add_argument(
        "--scan-types", 
        nargs="+",
        choices=['xss', 'sqli', 'all'],
        default=['all'],
        help="Types of vulnerabilities to scan for"
    )
    
    return parser.parse_args()

def validate_arguments(args):
    """Validate command line arguments"""
    # Validate URL
    if not args.url.startswith(('http://', 'https://')):
        print("[!] Error: URL must start with http:// or https://")
        return False
    
    # Validate payloads file
    if not os.path.exists(args.payloads):
        print(f"[!] Error: Payloads file not found: {args.payloads}")
        return False
    
    # Validate threads
    if args.threads < 1 or args.threads > 50:
        print("[!] Error: Threads must be between 1 and 50")
        return False
    
    # Validate depth
    if args.depth < 1 or args.depth > 10:
        print("[!] Error: Depth must be between 1 and 10")
        return False
    
    return True

def main():
    """Main function"""
    banner()
    
    # Parse arguments
    args = parse_arguments()
    
    # Validate arguments
    if not validate_arguments(args):
        sys.exit(1)
    
    # Setup logger
    logger = setup_logger(verbose=args.verbose)
    
    # Create output directory if needed
    if args.output:
        output_dir = os.path.dirname(args.output)
        if output_dir and not os.path.exists(output_dir):
            os.makedirs(output_dir)
    
    # Generate default output filename if not provided
    if not args.output:
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        os.makedirs("reports", exist_ok=True)
        args.output = f"reports/scan_{timestamp}.{args.format}"
    
    # Load configuration
    config = Config(
        target_url=args.url,
        depth=args.depth,
        threads=args.threads,
        payloads_file=args.payloads,
        auth_cookie=args.auth_cookie,
        proxy=args.proxy,
        timeout=args.timeout,
        user_agent=args.user_agent,
        scan_types=args.scan_types
    )
    
    try:
        logger.info(f"Starting PyWebScan on target: {args.url}")
        logger.info(f"Configuration: Depth={args.depth}, Threads={args.threads}")
        
        # Initialize components
        crawler = WebCrawler(config)
        scanner = VulnerabilityScanner(config)
        report_generator = ReportGenerator()
        
        # Step 1: Crawling
        if not args.no_crawl:
            logger.info("Phase 1: Web Crawling")
            urls = crawler.crawl()
            logger.info(f"Found {len(urls)} URLs to scan")
        else:
            urls = [args.url]
            logger.info("Skipping crawl phase, scanning single URL")
        
        # Step 2: Vulnerability Scanning
        logger.info("Phase 2: Vulnerability Scanning")
        results = scanner.scan_urls(urls)
        
        # Step 3: Report Generation
        logger.info("Phase 3: Report Generation")
        report_generator.generate(
            results, 
            config, 
            args.output, 
            args.format
        )
        
        # Summary
        total_vulns = sum(len(result.vulnerabilities) for result in results)
        logger.info(f"Scan completed! Found {total_vulns} vulnerabilities")
        logger.info(f"Report saved to: {args.output}")
        
        # Print summary to console
        print(f"\n{'='*60}")
        print(f"SCAN SUMMARY")
        print(f"{'='*60}")
        print(f"Target URL: {args.url}")
        print(f"URLs Scanned: {len(urls)}")
        print(f"Vulnerabilities Found: {total_vulns}")
        print(f"Report Location: {args.output}")
        print(f"{'='*60}")
        
        # Return appropriate exit code
        sys.exit(0 if total_vulns == 0 else 1)
        
    except KeyboardInterrupt:
        logger.warning("Scan interrupted by user")
        sys.exit(130)
    except Exception as e:
        logger.error(f"Unexpected error: {str(e)}")
        if args.verbose:
            import traceback
            traceback.print_exc()
        sys.exit(1)

if __name__ == "__main__":
    main()