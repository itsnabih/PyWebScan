"""
Advanced web crawler for PyWebScan
Discovers URLs, forms, and potential attack vectors
"""

import requests
import time
import re
from urllib.parse import urljoin, urlparse, parse_qs, urlencode, urlunparse
from bs4 import BeautifulSoup
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import List, Set, Dict, Tuple, Optional
from dataclasses import dataclass
from utils.logger import setup_logger

@dataclass
class FormInfo:
    """Information about an HTML form"""
    action: str
    method: str
    inputs: List[Dict[str, str]]
    url: str  # URL where the form was found
    
    def get_test_data(self) -> Dict[str, str]:
        """Generate test data for form inputs"""
        test_data = {}
        for input_field in self.inputs:
            name = input_field.get('name', '')
            input_type = input_field.get('type', 'text').lower()
            
            if not name:
                continue
            
            # Generate appropriate test data based on input type
            if input_type in ['text', 'search']:
                test_data[name] = 'test'
            elif input_type == 'email':
                test_data[name] = 'test@example.com'
            elif input_type == 'password':
                test_data[name] = 'password123'
            elif input_type in ['number', 'range']:
                test_data[name] = '1'
            elif input_type == 'url':
                test_data[name] = 'http://example.com'
            elif input_type == 'tel':
                test_data[name] = '1234567890'
            elif input_type == 'hidden':
                # Keep existing value or set to empty
                test_data[name] = input_field.get('value', '')
            elif input_type in ['checkbox', 'radio']:
                # Only include if it has a value
                if 'value' in input_field:
                    test_data[name] = input_field['value']
            else:
                test_data[name] = 'test'
        
        return test_data

@dataclass
class CrawlResult:
    """Result of crawling operation"""
    urls: Set[str]
    forms: List[FormInfo]
    parameters: Dict[str, Set[str]]  # URL -> set of parameter names
    external_links: Set[str]
    javascript_files: Set[str]
    comments: List[str]

class WebCrawler:
    """Advanced web crawler with form detection and parameter extraction"""
    
    def __init__(self, config):
        self.config = config
        self.logger = setup_logger("Crawler", verbose=True)
        self.session = requests.Session()
        self.session.headers.update(config.get_request_headers())
        
        # Crawling state
        self.visited_urls = set()
        self.found_urls = set()
        self.found_forms = []
        self.url_parameters = {}
        self.external_links = set()
        self.javascript_files = set()
        self.comments = []
        
        # Request configuration
        self.request_kwargs = config.get_request_kwargs()
        
    def crawl(self) -> List[str]:
        """Main crawling method"""
        self.logger.info(f"Starting crawl of {self.config.target_url}")
        self.logger.info(f"Max depth: {self.config.depth}, Max URLs: {self.config.max_urls}")
        
        # Initialize with target URL
        self.found_urls.add(self.config.target_url)
        
        # Crawl level by level
        for depth in range(self.config.depth):
            current_level_urls = self.found_urls - self.visited_urls
            
            if not current_level_urls:
                break
                
            self.logger.info(f"Crawling depth {depth + 1}: {len(current_level_urls)} URLs")
            
            # Limit URLs per level to prevent explosion
            if len(current_level_urls) > 100:
                current_level_urls = list(current_level_urls)[:100]
                current_level_urls = set(current_level_urls)
            
            # Crawl URLs in parallel
            with ThreadPoolExecutor(max_workers=self.config.threads) as executor:
                futures = {executor.submit(self._crawl_url, url): url for url in current_level_urls}
                
                for future in as_completed(futures):
                    url = futures[future]
                    try:
                        result = future.result()
                        if result:
                            self._process_crawl_result(result, url)
                    except Exception as e:
                        self.logger.error(f"Error crawling {url}: {e}")
                    
                    # Respect rate limiting
                    time.sleep(self.config.delay_between_requests)
            
            # Check if we've reached max URLs
            if len(self.found_urls) >= self.config.max_urls:
                self.logger.warning(f"Reached maximum URL limit ({self.config.max_urls})")
                break
        
        # Return final results
        result = CrawlResult(
            urls=self.found_urls,
            forms=self.found_forms,
            parameters=self.url_parameters,
            external_links=self.external_links,
            javascript_files=self.javascript_files,
            comments=self.comments
        )
        
        self._log_crawl_summary(result)
        return list(self.found_urls)
    
    def _crawl_url(self, url: str) -> Optional[Dict]:
        """Crawl a single URL and extract information"""
        if url in self.visited_urls:
            return None
        
        try:
            self.logger.debug(f"Crawling: {url}")
            response = self.session.get(url, **self.request_kwargs)
            
            # Mark as visited
            self.visited_urls.add(url)
            
            # Only process HTML responses
            content_type = response.headers.get('content-type', '').lower()
            if 'text/html' not in content_type:
                return None
            
            soup = BeautifulSoup(response.text, 'html.parser')
            
            return {
                'url': url,
                'soup': soup,
                'response': response
            }
            
        except requests.RequestException as e:
            self.logger.error(f"Request failed for {url}: {e}")
            self.visited_urls.add(url)  # Mark as visited to avoid retry
            return None
        except Exception as e:
            self.logger.error(f"Unexpected error crawling {url}: {e}")
            return None
    
    def _process_crawl_result(self, result: Dict, base_url: str):
        """Process crawling result and extract information"""
        soup = result['soup']
        
        # Extract links
        new_urls = self._extract_links(soup, base_url)
        self.found_urls.update(new_urls)
        
        # Extract forms
        forms = self._extract_forms(soup, base_url)
        self.found_forms.extend(forms)
        
        # Extract URL parameters
        params = self._extract_url_parameters(base_url)
        if params:
            self.url_parameters[base_url] = params
        
        # Extract JavaScript files
        js_files = self._extract_javascript_files(soup, base_url)
        self.javascript_files.update(js_files)
        
        # Extract comments
        comments = self._extract_comments(soup)
        self.comments.extend(comments)
    
    def _extract_links(self, soup: BeautifulSoup, base_url: str) -> Set[str]:
        """Extract all links from the page"""
        links = set()
        
        # Extract from <a> tags
        for link in soup.find_all('a', href=True):
            href = link['href'].strip()
            full_url = urljoin(base_url, href)
            
            # Clean URL (remove fragment)
            parsed_url = urlparse(full_url)
            clean_url = urlunparse((
                parsed_url.scheme,
                parsed_url.netloc,
                parsed_url.path,
                parsed_url.params,
                parsed_url.query,
                ''  # Remove fragment
            ))
            
            if self.config.is_url_in_scope(clean_url):
                links.add(clean_url)
            else:
                self.external_links.add(clean_url)
        
        # Extract from forms (action URLs)
        for form in soup.find_all('form', action=True):
            action = form['action'].strip()
            if action:
                full_url = urljoin(base_url, action)
                if self.config.is_url_in_scope(full_url):
                    links.add(full_url)
        
        # Extract from JavaScript (basic regex patterns)
        for script in soup.find_all('script'):
            if script.string:
                # Look for URL patterns in JavaScript
                js_urls = re.findall(r'["\']([^"\']+\.(?:php|asp|aspx|jsp|html|htm)(?:\?[^"\']*)?)["\']', script.string)
                for js_url in js_urls:
                    full_url = urljoin(base_url, js_url)
                    if self.config.is_url_in_scope(full_url):
                        links.add(full_url)
        
        return links
    
    def _extract_forms(self, soup: BeautifulSoup, base_url: str) -> List[FormInfo]:
        """Extract form information from the page"""
        forms = []
        
        for form in soup.find_all('form'):
            action = form.get('action', '')
            method = form.get('method', 'GET').upper()
            
            # Resolve action URL
            if action:
                action_url = urljoin(base_url, action)
            else:
                action_url = base_url
            
            # Extract input fields
            inputs = []
            for input_tag in form.find_all(['input', 'textarea', 'select']):
                input_info = {
                    'name': input_tag.get('name', ''),
                    'type': input_tag.get('type', 'text'),
                    'value': input_tag.get('value', ''),
                    'tag': input_tag.name
                }
                
                # Handle select options
                if input_tag.name == 'select':
                    options = []
                    for option in input_tag.find_all('option'):
                        options.append(option.get('value', option.text))
                    input_info['options'] = options
                
                inputs.append(input_info)
            
            form_info = FormInfo(
                action=action_url,
                method=method,
                inputs=inputs,
                url=base_url
            )
            
            forms.append(form_info)
            self.logger.debug(f"Found form: {method} {action_url} ({len(inputs)} inputs)")
        
        return forms
    
    def _extract_url_parameters(self, url: str) -> Set[str]:
        """Extract parameter names from URL"""
        parsed_url = urlparse(url)
        if parsed_url.query:
            params = parse_qs(parsed_url.query)
            return set(params.keys())
        return set()
    
    def _extract_javascript_files(self, soup: BeautifulSoup, base_url: str) -> Set[str]:
        """Extract JavaScript file URLs"""
        js_files = set()
        
        for script in soup.find_all('script', src=True):
            src = script['src'].strip()
            full_url = urljoin(base_url, src)
            js_files.add(full_url)
        
        return js_files
    
    def _extract_comments(self, soup: BeautifulSoup) -> List[str]:
        """Extract HTML comments that might contain sensitive information"""
        comments = []
        
        # Find HTML comments
        html_comments = soup.find_all(string=lambda text: isinstance(text, str) and text.strip().startswith('<!--'))
        
        for comment in html_comments:
            comment_text = comment.strip()
            # Look for potentially interesting comments
            if any(keyword in comment_text.lower() for keyword in ['todo', 'debug', 'password', 'admin', 'test', 'dev']):
                comments.append(comment_text)
        
        return comments
    
    def get_all_endpoints(self) -> List[str]:
        """Get all discovered endpoints including form actions"""
        endpoints = list(self.found_urls)
        
        # Add form action URLs
        for form in self.found_forms:
            if form.action not in endpoints:
                endpoints.append(form.action)
        
        return endpoints
    
    def get_forms(self) -> List[FormInfo]:
        """Get all discovered forms"""
        return self.found_forms
    
    def get_parameters(self) -> Dict[str, Set[str]]:
        """Get all discovered URL parameters"""
        return self.url_parameters
    
    def _log_crawl_summary(self, result: CrawlResult):
        """Log crawling summary"""
        self.logger.info("Crawling completed!")
        self.logger.info(f"URLs discovered: {len(result.urls)}")
        self.logger.info(f"Forms found: {len(result.forms)}")
        self.logger.info(f"URLs with parameters: {len(result.parameters)}")
        self.logger.info(f"External links: {len(result.external_links)}")
        self.logger.info(f"JavaScript files: {len(result.javascript_files)}")
        self.logger.info(f"Interesting comments: {len(result.comments)}")
        
        # Log some examples
        if result.forms:
            self.logger.info("Sample forms found:")
            for form in result.forms[:3]:  # Show first 3 forms
                self.logger.info(f"  {form.method} {form.action} ({len(form.inputs)} inputs)")
        
        if result.parameters:
            self.logger.info("URLs with parameters:")
            for url, params in list(result.parameters.items())[:3]:  # Show first 3
                self.logger.info(f"  {url} -> {', '.join(params)}")

class AdvancedCrawler(WebCrawler):
    """Enhanced crawler with additional features"""
    
    def __init__(self, config):
        super().__init__(config)
        self.robots_txt_urls = set()
        self.sitemap_urls = set()
    
    def crawl_with_discovery(self) -> List[str]:
        """Enhanced crawling with robots.txt and sitemap discovery"""
        # Check robots.txt
        self._check_robots_txt()
        
        # Check sitemap
        self._check_sitemap()
        
        # Perform regular crawling
        return self.crawl()
    
    def _check_robots_txt(self):
        """Check robots.txt for additional URLs"""
        robots_url = urljoin(self.config.target_url, '/robots.txt')
        
        try:
            response = self.session.get(robots_url, **self.request_kwargs)
            if response.status_code == 200:
                self.logger.info("Found robots.txt")
                
                # Extract URLs from robots.txt
                for line in response.text.split('\n'):
                    line = line.strip()
                    if line.startswith(('Disallow:', 'Allow:')):
                        path = line.split(':', 1)[1].strip()
                        if path and path != '/':
                            full_url = urljoin(self.config.target_url, path)
                            if self.config.is_url_in_scope(full_url):
                                self.robots_txt_urls.add(full_url)
                                self.found_urls.add(full_url)
                
                self.logger.info(f"Extracted {len(self.robots_txt_urls)} URLs from robots.txt")
        
        except Exception as e:
            self.logger.debug(f"Could not fetch robots.txt: {e}")
    
    def _check_sitemap(self):
        """Check sitemap.xml for additional URLs"""
        sitemap_urls = [
            '/sitemap.xml',
            '/sitemap_index.xml',
            '/sitemap1.xml'
        ]
        
        for sitemap_path in sitemap_urls:
            sitemap_url = urljoin(self.config.target_url, sitemap_path)
            
            try:
                response = self.session.get(sitemap_url, **self.request_kwargs)
                if response.status_code == 200:
                    self.logger.info(f"Found sitemap: {sitemap_path}")
                    
                    # Extract URLs from sitemap (basic XML parsing)
                    urls = re.findall(r'<loc>(.*?)</loc>', response.text)
                    for url in urls:
                        if self.config.is_url_in_scope(url):
                            self.sitemap_urls.add(url)
                            self.found_urls.add(url)
                    
                    self.logger.info(f"Extracted {len(urls)} URLs from {sitemap_path}")
                    break
            
            except Exception as e:
                self.logger.debug(f"Could not fetch {sitemap_path}: {e}")