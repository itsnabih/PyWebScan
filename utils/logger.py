"""
Logging utilities for PyWebScan
"""

import logging
import sys
import os
from datetime import datetime
from typing import Optional

try:
    from colorama import init, Fore, Back, Style
    init(autoreset=True)
    COLORAMA_AVAILABLE = True
except ImportError:
    COLORAMA_AVAILABLE = False

class ColorFormatter(logging.Formatter):
    """Custom formatter with color support"""
    
    def __init__(self):
        super().__init__()
        
        if COLORAMA_AVAILABLE:
            self.colors = {
                'DEBUG': Fore.CYAN,
                'INFO': Fore.GREEN,
                'WARNING': Fore.YELLOW,
                'ERROR': Fore.RED,
                'CRITICAL': Fore.RED + Back.WHITE + Style.BRIGHT,
            }
        else:
            self.colors = {}
    
    def format(self, record):
        """Format log record with colors"""
        timestamp = datetime.fromtimestamp(record.created).strftime('%H:%M:%S')
        level_name = record.levelname
        
        if COLORAMA_AVAILABLE and level_name in self.colors:
            level_colored = f"{self.colors[level_name]}{level_name:<8}{Style.RESET_ALL}"
        else:
            level_colored = f"{level_name:<8}"
        
        # Format the message
        if record.levelno >= logging.ERROR:
            prefix = "[!]" if COLORAMA_AVAILABLE else "[!]"
        elif record.levelno >= logging.WARNING:
            prefix = "[*]" if COLORAMA_AVAILABLE else "[*]"
        else:
            prefix = "[+]" if COLORAMA_AVAILABLE else "[+]"
        
        if COLORAMA_AVAILABLE:
            prefix = f"{Fore.WHITE}{Style.BRIGHT}{prefix}{Style.RESET_ALL}"
        
        return f"{Fore.BLUE if COLORAMA_AVAILABLE else ''}{timestamp}{Style.RESET_ALL if COLORAMA_AVAILABLE else ''} {level_colored} {prefix} {record.getMessage()}"

class PyWebScanLogger:
    """Custom logger for PyWebScan"""
    
    def __init__(self, name: str = "PyWebScan", verbose: bool = False):
        self.logger = logging.getLogger(name)
        self.logger.setLevel(logging.DEBUG if verbose else logging.INFO)
        
        # Clear existing handlers
        self.logger.handlers.clear()
        
        # Console handler
        console_handler = logging.StreamHandler(sys.stdout)
        console_handler.setFormatter(ColorFormatter())
        console_handler.setLevel(logging.DEBUG if verbose else logging.INFO)
        self.logger.addHandler(console_handler)
        
        # File handler (optional)
        self.file_handler = None
    
    def add_file_handler(self, log_file: str):
        """Add file handler for logging to file"""
        try:
            # Create log directory if it doesn't exist
            log_dir = os.path.dirname(log_file)
            if log_dir and not os.path.exists(log_dir):
                os.makedirs(log_dir)
            
            self.file_handler = logging.FileHandler(log_file, mode='a', encoding='utf-8')
            file_formatter = logging.Formatter(
                '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
            )
            self.file_handler.setFormatter(file_formatter)
            self.file_handler.setLevel(logging.DEBUG)
            self.logger.addHandler(self.file_handler)
            
            self.info(f"Log file created: {log_file}")
        except Exception as e:
            self.warning(f"Could not create log file {log_file}: {e}")
    
    def debug(self, message: str):
        """Log debug message"""
        self.logger.debug(message)
    
    def info(self, message: str):
        """Log info message"""
        self.logger.info(message)
    
    def warning(self, message: str):
        """Log warning message"""
        self.logger.warning(message)
    
    def error(self, message: str):
        """Log error message"""
        self.logger.error(message)
    
    def critical(self, message: str):
        """Log critical message"""
        self.logger.critical(message)
    
    def success(self, message: str):
        """Log success message (custom level)"""
        if COLORAMA_AVAILABLE:
            print(f"{Fore.GREEN}[✓] {message}{Style.RESET_ALL}")
        else:
            print(f"[✓] {message}")
    
    def vulnerability_found(self, vuln_type: str, url: str, payload: str = ""):
        """Log vulnerability finding"""
        vuln_color = Fore.RED + Back.YELLOW + Style.BRIGHT if COLORAMA_AVAILABLE else ""
        reset_color = Style.RESET_ALL if COLORAMA_AVAILABLE else ""
        
        message = f"{vuln_color}VULNERABILITY FOUND{reset_color} - {vuln_type.upper()} in {url}"
        if payload:
            message += f" (Payload: {payload[:50]}{'...' if len(payload) > 50 else ''})"
        
        self.logger.error(message)
    
    def scan_progress(self, current: int, total: int, url: str = ""):
        """Log scan progress"""
        percentage = (current / total) * 100 if total > 0 else 0
        progress_bar = self._create_progress_bar(percentage)
        
        message = f"Progress: {progress_bar} {current}/{total} ({percentage:.1f}%)"
        if url:
            message += f" - {url[:60]}{'...' if len(url) > 60 else ''}"
        
        # Use carriage return to overwrite the same line
        if current < total:
            print(f"\r{message}", end="", flush=True)
        else:
            print(f"\r{message}")
    
    def _create_progress_bar(self, percentage: float, width: int = 20) -> str:
        """Create a text-based progress bar"""
        filled = int(width * percentage / 100)
        bar = "█" * filled + "░" * (width - filled)
        
        if COLORAMA_AVAILABLE:
            return f"{Fore.GREEN}{bar}{Style.RESET_ALL}"
        else:
            return f"[{bar}]"
    
    def section_header(self, title: str):
        """Log section header"""
        separator = "=" * 60
        if COLORAMA_AVAILABLE:
            print(f"\n{Fore.CYAN}{Style.BRIGHT}{separator}")
            print(f"{title.center(60)}")
            print(f"{separator}{Style.RESET_ALL}\n")
        else:
            print(f"\n{separator}")
            print(f"{title.center(60)}")
            print(f"{separator}\n")
    
    def table_row(self, columns: list, widths: list = None):
        """Log table row"""
        if not widths:
            widths = [20] * len(columns)
        
        row = " | ".join(str(col).ljust(width)[:width] for col, width in zip(columns, widths))
        print(f"| {row} |")
    
    def table_separator(self, widths: list):
        """Log table separator"""
        separator = "-+-".join("-" * width for width in widths)
        print(f"+-{separator}-+")

def setup_logger(name: str = "PyWebScan", verbose: bool = False, log_file: Optional[str] = None) -> PyWebScanLogger:
    """Setup and return a configured logger"""
    logger = PyWebScanLogger(name, verbose)
    
    if log_file:
        logger.add_file_handler(log_file)
    
    return logger

# Global logger instance (can be imported directly)
logger = setup_logger()