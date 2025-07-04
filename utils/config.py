"""
Configuration management for PyWebScan
"""

import json
import os
from dataclasses import dataclass
from typing import List, Optional, Dict, Any
from urllib.parse import urlparse

@dataclass
class Config:
    """Main configuration class for PyWebScan"""
    
    # Target configuration
    target_url: str
    depth: int = 2
    threads: int = 10
    
    # File paths
    payloads_file: str = "payloads/payloads.json"
    
    # Authentication
    auth_cookie: Optional[str] = None
    auth_headers: Optional[Dict[str, str]] = None
    
    # Network settings
    proxy: Optional[str] = None
    timeout: int = 10
    user_agent: str = "PyWebScan/2.0"
    max_retries: int = 3
    delay_between_requests: float = 0.1
    
    # Scanning configuration
    scan_types: List[str] = None
    max_urls: int = 1000
    follow_redirects: bool = True
    verify_ssl: bool = False
    
    # Advanced options
    custom_headers: Optional[Dict[str, str]] = None
    excluded_extensions: List[str] = None
    included_domains: List[str] = None
    
    def __post_init__(self):
        """Post-initialization validation and setup"""
        if self.scan_types is None:
            self.scan_types = ['all']
        
        if self.excluded_extensions is None:
            self.excluded_extensions = [
                '.jpg', '.jpeg', '.png', '.gif', '.bmp', '.svg',
                '.pdf', '.doc', '.docx', '.xls', '.xlsx', '.ppt', '.pptx',
                '.zip', '.rar', '.tar', '.gz', '.mp3', '.mp4', '.avi',
                '.css', '.js', '.woff', '.woff2', '.ttf', '.eot'
            ]
        
        # Parse target domain for scope limiting
        parsed_url = urlparse(self.target_url)
        self.target_domain = parsed_url.netloc
        
        if self.included_domains is None:
            self.included_domains = [self.target_domain]
        
        # Validate scan types
        valid_scan_types = ['xss', 'sqli', 'all']
        if 'all' in self.scan_types:
            self.scan_types = ['xss', 'sqli']
        else:
            for scan_type in self.scan_types:
                if scan_type not in valid_scan_types:
                    raise ValueError(f"Invalid scan type: {scan_type}")
    
    def get_request_headers(self) -> Dict[str, str]:
        """Get headers for HTTP requests"""
        headers = {
            'User-Agent': self.user_agent,
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
            'Accept-Language': 'en-US,en;q=0.5',
            'Accept-Encoding': 'gzip, deflate',
            'Connection': 'keep-alive',
            'Upgrade-Insecure-Requests': '1',
        }
        
        # Add authentication cookie if provided
        if self.auth_cookie:
            headers['Cookie'] = self.auth_cookie
        
        # Add custom headers if provided
        if self.custom_headers:
            headers.update(self.custom_headers)
        
        # Add auth headers if provided
        if self.auth_headers:
            headers.update(self.auth_headers)
        
        return headers
    
    def get_request_kwargs(self) -> Dict[str, Any]:
        """Get kwargs for requests library"""
        kwargs = {
            'headers': self.get_request_headers(),
            'timeout': self.timeout,
            'allow_redirects': self.follow_redirects,
            'verify': self.verify_ssl,
        }
        
        if self.proxy:
            kwargs['proxies'] = {
                'http': self.proxy,
                'https': self.proxy
            }
        
        return kwargs
    
    def is_url_in_scope(self, url: str) -> bool:
        """Check if URL is within scanning scope"""
        try:
            parsed_url = urlparse(url)
            domain = parsed_url.netloc
            
            # Check if domain is in included domains
            if domain not in self.included_domains:
                return False
            
            # Check file extension
            path = parsed_url.path.lower()
            for ext in self.excluded_extensions:
                if path.endswith(ext):
                    return False
            
            return True
        except Exception:
            return False
    
    def load_payloads(self) -> Dict[str, List[str]]:
        """Load payloads from file"""
        try:
            with open(self.payloads_file, 'r', encoding='utf-8') as f:
                return json.load(f)
        except FileNotFoundError:
            raise FileNotFoundError(f"Payloads file not found: {self.payloads_file}")
        except json.JSONDecodeError as e:
            raise ValueError(f"Invalid JSON in payloads file: {e}")
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert config to dictionary for reporting"""
        return {
            'target_url': self.target_url,
            'target_domain': self.target_domain,
            'depth': self.depth,
            'threads': self.threads,
            'scan_types': self.scan_types,
            'timeout': self.timeout,
            'user_agent': self.user_agent,
            'max_urls': self.max_urls,
            'follow_redirects': self.follow_redirects,
            'verify_ssl': self.verify_ssl,
            'has_auth': bool(self.auth_cookie or self.auth_headers),
            'has_proxy': bool(self.proxy),
        }

class PayloadManager:
    """Manages vulnerability detection payloads"""
    
    def __init__(self, config: Config):
        self.config = config
        self.payloads = config.load_payloads()
    
    def get_xss_payloads(self) -> List[str]:
        """Get XSS payloads"""
        return self.payloads.get('xss', [])
    
    def get_sqli_payloads(self) -> List[str]:
        """Get SQL injection payloads"""
        return self.payloads.get('sqli', [])
    
    def get_payloads_by_type(self, vuln_type: str) -> List[str]:
        """Get payloads by vulnerability type"""
        if vuln_type == 'xss':
            return self.get_xss_payloads()
        elif vuln_type == 'sqli':
            return self.get_sqli_payloads()
        else:
            return []
    
    def get_context_aware_xss_payloads(self, context: str = 'default') -> List[str]:
        """Get context-aware XSS payloads"""
        base_payloads = self.get_xss_payloads()
        
        context_payloads = {
            'script': [
                'alert(1)',
                'confirm(1)',
                'prompt(1)',
                'console.log("XSS")'
            ],
            'attribute': [
                '" onmouseover="alert(1)"',
                '" onclick="alert(1)"',
                '" onfocus="alert(1)"',
                '"><img src=x onerror=alert(1)>'
            ],
            'html': [
                '<img src=x onerror=alert(1)>',
                '<svg onload=alert(1)>',
                '<iframe src="javascript:alert(1)">',
                '<body onload=alert(1)>'
            ],
            'url': [
                'javascript:alert(1)',
                'data:text/html,<script>alert(1)</script>',
                'vbscript:msgbox("XSS")'
            ]
        }
        
        if context in context_payloads:
            return base_payloads + context_payloads[context]
        
        return base_payloads