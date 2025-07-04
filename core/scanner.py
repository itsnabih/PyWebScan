"""
Main vulnerability scanner engine for PyWebScan
Orchestrates XSS and SQL Injection scanning
"""

import time
from typing import List, Dict, Set, Optional
from dataclasses import dataclass, field
from enum import Enum
from concurrent.futures import ThreadPoolExecutor, as_completed

from core.xss import XSSScanner
from core.sqli import SQLiScanner
from core.crawler import FormInfo
from utils.http import HTTPClient
from utils.logger import setup_logger


class VulnerabilityType(Enum):
    XSS_REFLECTED = "XSS_REFLECTED"
    XSS_STORED = "XSS_STORED"
    XSS_DOM = "XSS_DOM"
    SQLI_ERROR = "SQLI_ERROR"
    SQLI_BOOLEAN = "SQLI_BOOLEAN"
    SQLI_TIME = "SQLI_TIME"
    SQLI_UNION = "SQLI_UNION"


@dataclass
class Vulnerability:
    """Represents a discovered vulnerability"""
    vuln_type: VulnerabilityType
    url: str
    parameter: str
    payload: str
    evidence: str
    severity: str = "Medium"
    confidence: str = "Medium"
    method: str = "GET"
    form_data: Optional[Dict[str, str]] = None
    response_time: float = 0.0
    status_code: int = 200
    additional_info: Dict[str, str] = field(default_factory=dict)
    
    def __post_init__(self):
        """Set severity and confidence based on vulnerability type"""
        severity_map = {
            VulnerabilityType.XSS_REFLECTED: ("High", "High"),
            VulnerabilityType.XSS_STORED: ("Critical", "High"),
            VulnerabilityType.XSS_DOM: ("Medium", "Medium"),
            VulnerabilityType.SQLI_ERROR: ("Critical", "High"),
            VulnerabilityType.SQLI_BOOLEAN: ("Critical", "Medium"),
            VulnerabilityType.SQLI_TIME: ("Critical", "High"),
            VulnerabilityType.SQLI_UNION: ("Critical", "High"),
        }
        
        if self.vuln_type in severity_map:
            self.severity, self.confidence = severity_map[self.vuln_type]


@dataclass
class ScanResult:
    """Result of scanning a URL"""
    url: str
    vulnerabilities: List[Vulnerability] = field(default_factory=list)
    scan_time: float = 0.0
    error: Optional[str] = None
    forms_tested: int = 0
    parameters_tested: int = 0


class VulnerabilityScanner:
    """Main vulnerability scanner that orchestrates XSS and SQL injection testing"""
    
    def __init__(self, config):
        self.config = config
        self.logger = setup_logger("VulnerabilityScanner", verbose=True)
        self.http_client = HTTPClient(config)
        
        # Initialize specialized scanners
        self.xss_scanner = XSSScanner(config, self.http_client)
        self.sqli_scanner = SQLiScanner(config, self.http_client)
    
    def scan_url(self, url: str, parameters: Set[str] = None) -> ScanResult:
        """Scan a single URL for vulnerabilities"""
        start_time = time.time()
        result = ScanResult(url=url)
        
        try:
            self.logger.info(f"Starting vulnerability scan for: {url}")
            
            # Scan for XSS vulnerabilities
            xss_vulns = self.xss_scanner.scan_url(url, parameters)
            result.vulnerabilities.extend(xss_vulns)
            
            # Scan for SQL injection vulnerabilities
            sqli_vulns = self.sqli_scanner.scan_url(url, parameters)
            result.vulnerabilities.extend(sqli_vulns)
            
            # Update scan statistics
            result.parameters_tested = len(parameters) if parameters else 0
            result.scan_time = time.time() - start_time
            
            self.logger.info(f"Scan completed for {url}. Found {len(result.vulnerabilities)} vulnerabilities")
            
        except Exception as e:
            result.error = str(e)
            result.scan_time = time.time() - start_time
            self.logger.error(f"Error scanning {url}: {e}")
        
        return result
    
    def scan_form(self, form: FormInfo) -> List[Vulnerability]:
        """Scan a form for vulnerabilities"""
        vulnerabilities = []
        
        try:
            self.logger.info(f"Starting form scan for: {form.action}")
            
            # Scan for XSS vulnerabilities in form
            xss_vulns = self.xss_scanner.scan_form(form)
            vulnerabilities.extend(xss_vulns)
            
            # Scan for SQL injection vulnerabilities in form
            sqli_vulns = self.sqli_scanner.scan_form(form)
            vulnerabilities.extend(sqli_vulns)
            
            self.logger.info(f"Form scan completed for {form.action}. Found {len(vulnerabilities)} vulnerabilities")
            
        except Exception as e:
            self.logger.error(f"Error scanning form {form.action}: {e}")
        
        return vulnerabilities
    
    def scan_urls_batch(self, urls: List[str], max_workers: int = 5) -> List[ScanResult]:
        """Scan multiple URLs concurrently"""
        results = []
        
        with ThreadPoolExecutor(max_workers=max_workers) as executor:
            # Submit all scan tasks
            future_to_url = {
                executor.submit(self.scan_url, url): url 
                for url in urls
            }
            
            # Collect results as they complete
            for future in as_completed(future_to_url):
                url = future_to_url[future]
                try:
                    result = future.result()
                    results.append(result)
                except Exception as e:
                    error_result = ScanResult(url=url, error=str(e))
                    results.append(error_result)
                    self.logger.error(f"Error in batch scan for {url}: {e}")
        
        return results
    
    def scan_forms_batch(self, forms: List[FormInfo], max_workers: int = 5) -> List[Vulnerability]:
        """Scan multiple forms concurrently"""
        vulnerabilities = []
        
        with ThreadPoolExecutor(max_workers=max_workers) as executor:
            # Submit all form scan tasks
            future_to_form = {
                executor.submit(self.scan_form, form): form 
                for form in forms
            }
            
            # Collect results as they complete
            for future in as_completed(future_to_form):
                form = future_to_form[future]
                try:
                    form_vulns = future.result()
                    vulnerabilities.extend(form_vulns)
                except Exception as e:
                    self.logger.error(f"Error in batch form scan for {form.action}: {e}")
        
        return vulnerabilities
    
    def get_scan_statistics(self, results: List[ScanResult]) -> Dict[str, any]:
        """Generate scan statistics"""
        total_urls = len(results)
        successful_scans = len([r for r in results if r.error is None])
        failed_scans = total_urls - successful_scans
        
        all_vulnerabilities = []
        for result in results:
            all_vulnerabilities.extend(result.vulnerabilities)
        
        total_vulnerabilities = len(all_vulnerabilities)
        vulnerability_types = {}
        severity_counts = {}
        
        for vuln in all_vulnerabilities:
            # Count by type
            vuln_type = vuln.vuln_type.value
            vulnerability_types[vuln_type] = vulnerability_types.get(vuln_type, 0) + 1
            
            # Count by severity
            severity = vuln.severity
            severity_counts[severity] = severity_counts.get(severity, 0) + 1
        
        return {
            'total_urls_scanned': total_urls,
            'successful_scans': successful_scans,
            'failed_scans': failed_scans,
            'total_vulnerabilities': total_vulnerabilities,
            'vulnerability_types': vulnerability_types,
            'severity_counts': severity_counts,
            'average_scan_time': sum(r.scan_time for r in results) / total_urls if total_urls > 0 else 0
        }
    
    def close(self):
        """Clean up resources"""
        if hasattr(self.http_client, 'close'):
            self.http_client.close()