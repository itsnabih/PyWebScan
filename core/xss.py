"""
XSS vulnerability scanner module
Handles detection of Cross-Site Scripting vulnerabilities
"""

import re
import time
from typing import List, Dict, Set, Optional
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse

from core.scanner import Vulnerability, VulnerabilityType
from core.crawler import FormInfo
from utils.logger import setup_logger


class XSSScanner:
    """XSS vulnerability scanner"""
    
    def __init__(self, config, http_client):
        self.config = config
        self.http_client = http_client
        self.logger = setup_logger("XSSScanner", verbose=True)
        
        # XSS detection patterns
        self.xss_patterns = [
            r'<script[^>]*>.*?alert\s*\([^)]*\).*?</script>',
            r'javascript:alert\s*\([^)]*\)',
            r'on\w+\s*=\s*["\']?[^"\']*alert\s*\([^)]*\)',
            r'<svg[^>]*onload\s*=\s*["\']?[^"\']*alert\s*\([^)]*\)',
            r'<img[^>]*onerror\s*=\s*["\']?[^"\']*alert\s*\([^)]*\)',
            r'eval\s*\(\s*["\'][^"\']*alert\s*\([^)]*\)',
            r'<iframe[^>]*src\s*=\s*["\']?javascript:alert\s*\([^)]*\)',
            r'<object[^>]*data\s*=\s*["\']?javascript:alert\s*\([^)]*\)',
            r'<embed[^>]*src\s*=\s*["\']?javascript:alert\s*\([^)]*\)',
        ]
        
        # Compile patterns for performance
        self.compiled_patterns = [re.compile(pattern, re.IGNORECASE) for pattern in self.xss_patterns]
        
        # Load XSS payloads
        self.payloads = self._load_xss_payloads()
    
    def _load_xss_payloads(self) -> List[str]:
        """Load XSS payloads from configuration or default set"""
        try:
            # Try to load from payload manager if available
            if hasattr(self.config, 'payload_manager'):
                return self.config.payload_manager.get_xss_payloads()
        except:
            pass
        
        # payloads
        return [
            '<script>alert("XSS")</script>',
            '<script>alert(1)</script>',
            '<img src=x onerror=alert("XSS")>',
            '<svg onload=alert("XSS")>',
            'javascript:alert("XSS")',
            '"><script>alert("XSS")</script>',
            "'><script>alert('XSS')</script>",
            '<iframe src=javascript:alert("XSS")>',
            '<object data=javascript:alert("XSS")>',
            '<embed src=javascript:alert("XSS")>',
            '<input onfocus=alert("XSS") autofocus>',
            '<select onfocus=alert("XSS") autofocus>',
            '<textarea onfocus=alert("XSS") autofocus>',
            '<keygen onfocus=alert("XSS") autofocus>',
            '<video><source onerror=alert("XSS")>',
            '<audio><source onerror=alert("XSS")>',
            '<details open ontoggle=alert("XSS")>',
            '<marquee onstart=alert("XSS")>',
            '<body onload=alert("XSS")>',
            '<div onmouseover=alert("XSS")>',
        ]
    
    def scan_url(self, url: str, parameters: Set[str] = None) -> List[Vulnerability]:
        """Scan URL for XSS vulnerabilities"""
        vulnerabilities = []
        
        if not parameters:
            # Extract parameters from URL
            parsed_url = urlparse(url)
            if parsed_url.query:
                parameters = set(parse_qs(parsed_url.query).keys())
            else:
                return vulnerabilities
        
        # Test each parameter
        for param in parameters:
            vulns = self._test_parameter_xss(url, param)
            vulnerabilities.extend(vulns)
        
        return vulnerabilities
    
    def scan_form(self, form: FormInfo) -> List[Vulnerability]:
        """Scan form for XSS vulnerabilities"""
        vulnerabilities = []
        
        if not form.inputs:
            return vulnerabilities
        
        # Get test data for the form
        base_data = form.get_test_data()
        
        # Test each input field
        for input_field in form.inputs:
            param_name = input_field.get('name', '')
            if not param_name or input_field.get('type', '').lower() in ['submit', 'button', 'image', 'reset']:
                continue
            
            vulns = self._test_form_input_xss(form, param_name, base_data)
            vulnerabilities.extend(vulns)
        
        return vulnerabilities
    
    def _test_parameter_xss(self, url: str, parameter: str) -> List[Vulnerability]:
        """Test a specific parameter for XSS"""
        vulnerabilities = []
        
        # Get base URL and parameters
        parsed_url = urlparse(url)
        base_params = parse_qs(parsed_url.query) if parsed_url.query else {}
        
        for payload in self.payloads:
            try:
                # Create test URL with payload
                test_params = base_params.copy()
                test_params[parameter] = [payload]
                
                query_string = urlencode(test_params, doseq=True)
                test_url = urlunparse((
                    parsed_url.scheme,
                    parsed_url.netloc,
                    parsed_url.path,
                    parsed_url.params,
                    query_string,
                    ''
                ))
                
                # Send request
                start_time = time.time()
                response = self.http_client.get(test_url)
                response_time = time.time() - start_time
                
                # Check for XSS
                if self._detect_xss_in_response(response.text, payload):
                    vulnerability = Vulnerability(
                        vuln_type=VulnerabilityType.XSS_REFLECTED,
                        url=test_url,
                        parameter=parameter,
                        payload=payload,
                        evidence=self._extract_evidence(response.text, payload),
                        method="GET",
                        response_time=response_time,
                        status_code=response.status_code
                    )
                    vulnerabilities.append(vulnerability)
                    self.logger.info(f"XSS vulnerability found: {test_url} - Parameter: {parameter}")
                    break  # One payload per parameter is enough
                
                # Rate limiting
                if hasattr(self.config, 'delay_between_requests'):
                    time.sleep(self.config.delay_between_requests)
                
            except Exception as e:
                self.logger.error(f"Error testing XSS on {url} parameter {parameter}: {e}")
        
        return vulnerabilities
    
    def _test_form_input_xss(self, form: FormInfo, parameter: str, base_data: Dict[str, str]) -> List[Vulnerability]:
        """Test form input for XSS"""
        vulnerabilities = []
        
        for payload in self.payloads:
            try:
                # Create form data with payload
                form_data = base_data.copy()
                form_data[parameter] = payload
                
                # Send request
                start_time = time.time()
                if form.method.upper() == 'POST':
                    response = self.http_client.post(form.action, data=form_data)
                else:
                    response = self.http_client.get(form.action, params=form_data)
                
                response_time = time.time() - start_time
                
                # Check for XSS
                if self._detect_xss_in_response(response.text, payload):
                    vulnerability = Vulnerability(
                        vuln_type=VulnerabilityType.XSS_REFLECTED,
                        url=form.action,
                        parameter=parameter,
                        payload=payload,
                        evidence=self._extract_evidence(response.text, payload),
                        method=form.method,
                        form_data=form_data,
                        response_time=response_time,
                        status_code=response.status_code
                    )
                    vulnerabilities.append(vulnerability)
                    self.logger.info(f"XSS vulnerability found in form: {form.action} - Parameter: {parameter}")
                    break
                
                # Rate limiting
                if hasattr(self.config, 'delay_between_requests'):
                    time.sleep(self.config.delay_between_requests)
                
            except Exception as e:
                self.logger.error(f"Error testing XSS on form {form.action} parameter {parameter}: {e}")
        
        return vulnerabilities
    
    def _detect_xss_in_response(self, response_text: str, payload: str) -> bool:
        """Detect XSS vulnerability in response"""
        # Simple payload reflection check
        if payload in response_text:
            return True
        
        # Pattern-based detection
        for pattern in self.compiled_patterns:
            if pattern.search(response_text):
                return True
        
        # Check for common XSS indicators
        xss_indicators = [
            'alert(',
            'confirm(',
            'prompt(',
            'javascript:',
            'onload=',
            'onerror=',
            'onclick=',
            'onmouseover=',
            'onfocus=',
            'onblur=',
            'onchange=',
            'onsubmit=',
        ]
        
        response_lower = response_text.lower()
        for indicator in xss_indicators:
            if indicator in response_lower and payload.lower() in response_lower:
                return True
        
        return False
    
    def _extract_evidence(self, response_text: str, payload: str) -> str:
        """Extract evidence of XSS vulnerability"""
        # Find the context where payload appears
        payload_index = response_text.find(payload)
        if payload_index != -1:
            start = max(0, payload_index - 50)
            end = min(len(response_text), payload_index + len(payload) + 50)
            return response_text[start:end]
        
        # Look for pattern matches
        for pattern in self.compiled_patterns:
            match = pattern.search(response_text)
            if match:
                return match.group(0)
        
        return "XSS payload detected in response"
    
    def test_stored_xss(self, url: str, payload: str, check_urls: List[str]) -> Optional[Vulnerability]:
        """Test for stored XSS by submitting payload and checking other pages"""
        try:
            # Submit payload (implementation depends on the form structure)
            # This is a simplified example
            response = self.http_client.post(url, data={'content': payload})
            
            if response.status_code == 200:
                # Check other pages for the payload
                for check_url in check_urls:
                    check_response = self.http_client.get(check_url)
                    if self._detect_xss_in_response(check_response.text, payload):
                        return Vulnerability(
                            vuln_type=VulnerabilityType.XSS_STORED,
                            url=check_url,
                            parameter="content",
                            payload=payload,
                            evidence=self._extract_evidence(check_response.text, payload),
                            method="POST",
                            status_code=check_response.status_code
                        )
        
        except Exception as e:
            self.logger.error(f"Error testing stored XSS: {e}")
        
        return None
    
    def test_dom_xss(self, url: str) -> List[Vulnerability]:
        """Test for DOM-based XSS vulnerabilities"""
        vulnerabilities = []
        
        # DOM XSS payloads that work with URL fragments
        dom_payloads = [
            '#<script>alert("DOM XSS")</script>',
            '#<img src=x onerror=alert("DOM XSS")>',
            '#javascript:alert("DOM XSS")',
            '#<svg onload=alert("DOM XSS")>',
        ]
        
        for payload in dom_payloads:
            try:
                test_url = url + payload
                response = self.http_client.get(test_url)
                
                # Check for DOM XSS indicators in JavaScript code
                if self._detect_dom_xss_in_response(response.text, payload):
                    vulnerability = Vulnerability(
                        vuln_type=VulnerabilityType.XSS_DOM,
                        url=test_url,
                        parameter="fragment",
                        payload=payload,
                        evidence=self._extract_evidence(response.text, payload),
                        method="GET",
                        status_code=response.status_code
                    )
                    vulnerabilities.append(vulnerability)
                    self.logger.info(f"DOM XSS vulnerability found: {test_url}")
                
            except Exception as e:
                self.logger.error(f"Error testing DOM XSS on {url}: {e}")
        
        return vulnerabilities
    
    def _detect_dom_xss_in_response(self, response_text: str, payload: str) -> bool:
        """Detect DOM-based XSS in response"""
        # Look for JavaScript code that processes URL fragments or parameters
        dom_patterns = [
            r'location\.hash',
            r'location\.search',
            r'document\.URL',
            r'window\.location',
            r'document\.location',
            r'document\.referrer',
            r'window\.name',
            r'history\.pushState',
            r'history\.replaceState',
        ]
        
        response_lower = response_text.lower()
        
        # Check if payload appears in potentially dangerous contexts
        for pattern in dom_patterns:
            if re.search(pattern, response_lower, re.IGNORECASE):
                # Check if payload is reflected in JavaScript context
                if payload.lower().replace('#', '') in response_lower:
                    return True
        
        return False