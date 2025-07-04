"""
HTTP client wrapper with logging and session management for WebScan vulnerability scanner
"""

import requests
import time
import json
from typing import Dict, Optional, Any, List, Union
from urllib.parse import urljoin, urlparse
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry
from urllib3.exceptions import InsecureRequestWarning
import urllib3

from utils.logger import setup_logger


class HTTPClient:
    """HTTP client wrapper with advanced features for vulnerability scanning"""
    
    def __init__(self, config):
        self.config = config
        self.logger = setup_logger("HTTPClient", verbose=getattr(config, 'verbose', False))
        self.session = requests.Session()
        
        # Setup session configuration
        self._setup_session()
        
        # Request statistics
        self.stats = {
            'total_requests': 0,
            'successful_requests': 0,
            'failed_requests': 0,
            'total_response_time': 0.0,
            'errors': [],
            'vulnerabilities_found': 0
        }
        
        # Rate limiting
        self.last_request_time = 0
        self.request_delay = getattr(config, 'request_delay', 0.1)  # Default 100ms delay
        
        # Disable SSL warnings if verification is disabled
        if not getattr(config, 'verify_ssl', True):
            urllib3.disable_warnings(InsecureRequestWarning)
    
    def _setup_session(self):
        """Setup session with headers, retries, and adapters"""
        # Set default headers to mimic real browser
        default_headers = {
            'User-Agent': getattr(self.config, 'user_agent', 
                'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36'),
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8',
            'Accept-Language': 'en-US,en;q=0.9',
            'Accept-Encoding': 'gzip, deflate, br',
            'Connection': 'keep-alive',
            'Upgrade-Insecure-Requests': '1',
            'Sec-Fetch-Dest': 'document',
            'Sec-Fetch-Mode': 'navigate',
            'Sec-Fetch-Site': 'none',
            'Cache-Control': 'max-age=0'
        }
        
        # Update with custom headers from config
        if hasattr(self.config, 'headers') and self.config.headers:
            default_headers.update(self.config.headers)
        
        self.session.headers.update(default_headers)
        
        # Setup retry strategy
        retry_strategy = Retry(
            total=getattr(self.config, 'max_retries', 3),
            backoff_factor=getattr(self.config, 'backoff_factor', 0.3),
            status_forcelist=[429, 500, 502, 503, 504],
            method_whitelist=["HEAD", "GET", "OPTIONS", "POST", "PUT", "DELETE", "PATCH"]
        )
        
        adapter = HTTPAdapter(
            max_retries=retry_strategy,
            pool_connections=getattr(self.config, 'pool_connections', 10),
            pool_maxsize=getattr(self.config, 'pool_maxsize', 10)
        )
        
        self.session.mount("http://", adapter)
        self.session.mount("https://", adapter)
        
        # Set timeouts
        self.timeout = getattr(self.config, 'timeout', 10)
        
        # Set proxies if configured
        if hasattr(self.config, 'proxy') and self.config.proxy:
            self.session.proxies = self.config.proxy
            self.logger.info(f"Using proxy: {self.config.proxy}")
        
        # SSL verification settings
        self.session.verify = getattr(self.config, 'verify_ssl', True)
        if not self.session.verify:
            self.logger.warning("SSL verification disabled")
        
        # Cookie jar
        if hasattr(self.config, 'cookies') and self.config.cookies:
            self.session.cookies.update(self.config.cookies)
    
    def _rate_limit(self):
        """Implement rate limiting between requests"""
        current_time = time.time()
        elapsed = current_time - self.last_request_time
        
        if elapsed < self.request_delay:
            sleep_time = self.request_delay - elapsed
            time.sleep(sleep_time)
        
        self.last_request_time = time.time()
    
    def _request(self, method: str, url: str, **kwargs) -> Optional[requests.Response]:
        """Internal method to handle all HTTP requests"""
        start_time = time.time()
        
        try:
            # Apply rate limiting
            self._rate_limit()
            
            # Set default timeout if not provided
            if 'timeout' not in kwargs:
                kwargs['timeout'] = self.timeout
            
            # Make the request
            self.logger.debug(f"Making {method} request to: {url}")
            response = self.session.request(method, url, **kwargs)
            
            # Calculate response time
            response_time = time.time() - start_time
            
            # Update statistics
            self.stats['total_requests'] += 1
            self.stats['total_response_time'] += response_time
            
            if response.status_code < 400:
                self.stats['successful_requests'] += 1
                self.logger.debug(f"Request successful: {response.status_code} - {response_time:.2f}s")
            else:
                self.stats['failed_requests'] += 1
                self.logger.warning(f"Request failed: {response.status_code} - {response_time:.2f}s")
            
            # Log response details for debugging
            self.logger.debug(f"Response headers: {dict(response.headers)}")
            
            return response
            
        except requests.exceptions.RequestException as e:
            self.stats['total_requests'] += 1
            self.stats['failed_requests'] += 1
            self.stats['errors'].append({
                'url': url,
                'method': method,
                'error': str(e),
                'timestamp': time.time()
            })
            
            self.logger.error(f"Request failed: {method} {url} - {str(e)}")
            return None
    
    def get(self, url: str, params: Optional[Dict[str, Any]] = None, **kwargs) -> Optional[requests.Response]:
        """Send GET request"""
        return self._request('GET', url, params=params, **kwargs)
    
    def post(self, url: str, data: Optional[Dict[str, Any]] = None, 
             json: Optional[Dict[str, Any]] = None, **kwargs) -> Optional[requests.Response]:
        """Send POST request"""
        return self._request('POST', url, data=data, json=json, **kwargs)
    
    def put(self, url: str, data: Optional[Dict[str, Any]] = None, 
            json: Optional[Dict[str, Any]] = None, **kwargs) -> Optional[requests.Response]:
        """Send PUT request"""
        return self._request('PUT', url, data=data, json=json, **kwargs)
    
    def delete(self, url: str, **kwargs) -> Optional[requests.Response]:
        """Send DELETE request"""
        return self._request('DELETE', url, **kwargs)
    
    def patch(self, url: str, data: Optional[Dict[str, Any]] = None, 
              json: Optional[Dict[str, Any]] = None, **kwargs) -> Optional[requests.Response]:
        """Send PATCH request"""
        return self._request('PATCH', url, data=data, json=json, **kwargs)
    
    def head(self, url: str, **kwargs) -> Optional[requests.Response]:
        """Send HEAD request"""
        return self._request('HEAD', url, **kwargs)
    
    def options(self, url: str, **kwargs) -> Optional[requests.Response]:
        """Send OPTIONS request"""
        return self._request('OPTIONS', url, **kwargs)
    
    def send_payload(self, url: str, payload: str, method: str = 'GET', 
                    param_name: str = 'q', **kwargs) -> Optional[requests.Response]:
        """Send a specific payload for vulnerability testing"""
        if method.upper() == 'GET':
            params = {param_name: payload}
            return self.get(url, params=params, **kwargs)
        elif method.upper() == 'POST':
            data = {param_name: payload}
            return self.post(url, data=data, **kwargs)
        else:
            return self._request(method, url, **kwargs)
    
    def test_multiple_payloads(self, url: str, payloads: List[str], 
                              method: str = 'GET', param_name: str = 'q') -> List[requests.Response]:
        """Test multiple payloads against a URL"""
        responses = []
        
        for payload in payloads:
            self.logger.debug(f"Testing payload: {payload[:50]}...")
            response = self.send_payload(url, payload, method, param_name)
            if response:
                responses.append(response)
            
            # Add delay between payload tests
            time.sleep(self.request_delay)
        
        return responses
    
    def is_url_accessible(self, url: str) -> bool:
        """Check if URL is accessible"""
        try:
            response = self.head(url)
            return response is not None and response.status_code < 400
        except:
            return False
    
    def get_server_info(self, url: str) -> Dict[str, Any]:
        """Get server information from headers"""
        response = self.head(url)
        if not response:
            return {}
        
        server_info = {}
        headers = response.headers
        
        # Extract server information
        server_info['server'] = headers.get('Server', 'Unknown')
        server_info['powered_by'] = headers.get('X-Powered-By', 'Unknown')
        server_info['technology'] = headers.get('X-Technology', 'Unknown')
        server_info['framework'] = headers.get('X-Framework', 'Unknown')
        server_info['content_type'] = headers.get('Content-Type', 'Unknown')
        server_info['last_modified'] = headers.get('Last-Modified', 'Unknown')
        
        # Security headers
        security_headers = [
            'X-Frame-Options', 'X-XSS-Protection', 'X-Content-Type-Options',
            'Strict-Transport-Security', 'Content-Security-Policy',
            'X-Permitted-Cross-Domain-Policies', 'Referrer-Policy'
        ]
        
        server_info['security_headers'] = {}
        for header in security_headers:
            server_info['security_headers'][header] = headers.get(header, 'Not Set')
        
        return server_info
    
    def get_forms(self, url: str) -> List[Dict[str, Any]]:
        """Extract forms from a webpage"""
        response = self.get(url)
        if not response:
            return []
        
        try:
            from bs4 import BeautifulSoup
            soup = BeautifulSoup(response.text, 'html.parser')
            forms = []
            
            for form in soup.find_all('form'):
                form_data = {
                    'action': form.get('action', ''),
                    'method': form.get('method', 'GET').upper(),
                    'inputs': []
                }
                
                # Make action URL absolute
                if form_data['action']:
                    form_data['action'] = urljoin(url, form_data['action'])
                else:
                    form_data['action'] = url
                
                # Extract input fields
                for input_field in form.find_all(['input', 'textarea', 'select']):
                    field_data = {
                        'name': input_field.get('name', ''),
                        'type': input_field.get('type', 'text'),
                        'value': input_field.get('value', ''),
                        'tag': input_field.name
                    }
                    
                    if field_data['name']:
                        form_data['inputs'].append(field_data)
                
                forms.append(form_data)
            
            return forms
            
        except ImportError:
            self.logger.warning("BeautifulSoup not installed. Cannot parse forms.")
            return []
        except Exception as e:
            self.logger.error(f"Error parsing forms: {str(e)}")
            return []
    
    def get_links(self, url: str) -> List[str]:
        """Extract links from a webpage"""
        response = self.get(url)
        if not response:
            return []
        
        try:
            from bs4 import BeautifulSoup
            soup = BeautifulSoup(response.text, 'html.parser')
            links = []
            
            for link in soup.find_all('a', href=True):
                href = link['href']
                absolute_url = urljoin(url, href)
                
                # Filter out non-HTTP links
                if absolute_url.startswith(('http://', 'https://')):
                    links.append(absolute_url)
            
            return list(set(links))  # Remove duplicates
            
        except ImportError:
            self.logger.warning("BeautifulSoup not installed. Cannot parse links.")
            return []
        except Exception as e:
            self.logger.error(f"Error parsing links: {str(e)}")
            return []
    
    def get_cookies(self) -> Dict[str, str]:
        """Get current session cookies"""
        return dict(self.session.cookies)
    
    def set_cookie(self, name: str, value: str, domain: Optional[str] = None):
        """Set a cookie for the session"""
        self.session.cookies.set(name, value, domain=domain)
    
    def clear_cookies(self):
        """Clear all cookies"""
        self.session.cookies.clear()
    
    def get_stats(self) -> Dict[str, Any]:
        """Get request statistics"""
        stats = self.stats.copy()
        
        if stats['total_requests'] > 0:
            stats['average_response_time'] = stats['total_response_time'] / stats['total_requests']
            stats['success_rate'] = (stats['successful_requests'] / stats['total_requests']) * 100
        else:
            stats['average_response_time'] = 0
            stats['success_rate'] = 0
        
        return stats
    
    def reset_stats(self):
        """Reset request statistics"""
        self.stats = {
            'total_requests': 0,
            'successful_requests': 0,
            'failed_requests': 0,
            'total_response_time': 0.0,
            'errors': [],
            'vulnerabilities_found': 0
        }
    
    def close(self):
        """Close the session"""
        self.session.close()
        self.logger.info("HTTP session closed")
    
    def __enter__(self):
        """Context manager entry"""
        return self
    
    def __exit__(self, exc_type, exc_val, exc_tb):
        """Context manager exit"""
        self.close()


class HTTPConfig:
    """Configuration class for HTTP client"""
    
    def __init__(self, **kwargs):
        # Basic settings
        self.timeout = kwargs.get('timeout', 10)
        self.max_retries = kwargs.get('max_retries', 3)
        self.backoff_factor = kwargs.get('backoff_factor', 0.3)
        self.request_delay = kwargs.get('request_delay', 0.1)
        
        # Headers
        self.user_agent = kwargs.get('user_agent', 
            'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36')
        self.headers = kwargs.get('headers', {})
        
        # Proxy settings
        self.proxy = kwargs.get('proxy', None)
        
        # SSL settings
        self.verify_ssl = kwargs.get('verify_ssl', True)
        
        # Connection pool settings
        self.pool_connections = kwargs.get('pool_connections', 10)
        self.pool_maxsize = kwargs.get('pool_maxsize', 10)
        
        # Cookies
        self.cookies = kwargs.get('cookies', {})
        
        # Logging
        self.verbose = kwargs.get('verbose', False)
    
    @classmethod
    def from_dict(cls, config_dict: Dict[str, Any]) -> 'HTTPConfig':
        """Create configuration from dictionary"""
        return cls(**config_dict)
    
    @classmethod
    def from_json(cls, json_str: str) -> 'HTTPConfig':
        """Create configuration from JSON string"""
        config_dict = json.loads(json_str)
        return cls.from_dict(config_dict)


# Factory function for easy HTTP client creation
def create_http_client(config: Union[HTTPConfig, Dict[str, Any], None] = None) -> HTTPClient:
    """Create HTTP client with configuration"""
    if config is None:
        config = HTTPConfig()
    elif isinstance(config, dict):
        config = HTTPConfig.from_dict(config)
    
    return HTTPClient(config)