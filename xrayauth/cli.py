#!/usr/bin/env python3

import argparse
import asyncio
import configparser
import json
import logging
import os
import re
import signal
import sys
import threading
from datetime import datetime
from typing import Dict, Optional, Tuple

try:
from scapy.all import sniff, TCP, Raw
from scapy.layers.http import HTTPRequest
    SCAPY_AVAILABLE = True
except ImportError as e:
    SCAPY_AVAILABLE = False
    logging.error(f"Scapy import failed: {e}")

# Configuration
CONFIG_FILE = os.path.expanduser("~/.xrayauth_config.ini")
DEFAULT_CONFIG = {
    'interface': 'eth0',
    'log': os.path.expanduser('~/xrayauth_logs.json'),
    'log_level': 'INFO'
}

# Global variables
session_db: Dict[str, Dict] = {}
stop_event = threading.Event()

# Token patterns for detection
TOKEN_PATTERNS = [
    re.compile(rb"Cookie:.*?session=.*?\r\n", re.IGNORECASE),
    re.compile(rb"Authorization: Bearer (.*?)\r\n", re.IGNORECASE)
]

# Setup logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.StreamHandler(sys.stdout),
        logging.FileHandler('xrayauth.log')
    ]
)
logger = logging.getLogger(__name__)


class XRayAuthError(Exception):
    """Custom exception for XRayAuth specific errors"""
    pass


class ConfigManager:
    """Manages configuration loading and saving"""
    
    @staticmethod
    def load_config() -> Dict[str, str]:
        """Load configuration from file or create default"""
        try:
            config = configparser.ConfigParser()
            if os.path.exists(CONFIG_FILE):
                config.read(CONFIG_FILE)
                return dict(config['XRayAuth'])
            else:
                return ConfigManager.create_default_config()
        except Exception as e:
            logger.warning(f"Failed to load config: {e}. Using defaults.")
            return DEFAULT_CONFIG.copy()
    
    @staticmethod
    def create_default_config() -> Dict[str, str]:
        """Create and save default configuration"""
        try:
            config = configparser.ConfigParser()
            config['XRayAuth'] = DEFAULT_CONFIG
            
            os.makedirs(os.path.dirname(CONFIG_FILE), exist_ok=True)
            with open(CONFIG_FILE, 'w') as configfile:
                config.write(configfile)
            
            logger.info(f"Created default config at {CONFIG_FILE}")
            return DEFAULT_CONFIG.copy()
        except Exception as e:
            logger.error(f"Failed to create config file: {e}")
            return DEFAULT_CONFIG.copy()


class SessionTracker:
    """Manages session tracking and anomaly detection"""
    
    def __init__(self, log_file: str):
        self.log_file = log_file
        self.session_db: Dict[str, Dict] = {}
    
    def log_event(self, entry: Dict) -> None:
        """Log event to file with proper error handling"""
        try:
            entry['timestamp'] = datetime.now().isoformat()
            with open(self.log_file, 'a', encoding='utf-8') as f:
                f.write(json.dumps(entry, ensure_ascii=False) + "\n")
        except Exception as e:
            logger.error(f"Failed to log event: {e}")
    
    def detect_anomaly(self, src_ip: str, token: str, user_agent: str) -> None:
        """Detect session hijacking anomalies"""
        try:
            if token in self.session_db:
                existing = self.session_db[token]
                if existing['ip'] != src_ip:
                    logger.warning("Possible Session Hijack Detected!")
                    print(f"\n[!] Possible Session Hijack Detected!")
                    print(f"[-] Token reused from new IP: {src_ip}")
                    print(f"[-] Old IP: {existing['ip']}, Old UA: {existing['ua']}\n")
                    
                    self.log_event({
                        "type": "anomaly",
                        "token": token[:50] + "..." if len(token) > 50 else token,  # Truncate for security
                        "new_ip": src_ip,
                        "old_ip": existing['ip'],
                        "old_ua": existing['ua'],
                        "new_ua": user_agent
                    })
            else:
                self.session_db[token] = {"ip": src_ip, "ua": user_agent}
                self.log_event({
                    "type": "new_session", 
                    "ip": src_ip, 
                    "ua": user_agent, 
                    "token": token[:50] + "..." if len(token) > 50 else token
                })
        except Exception as e:
            logger.error(f"Error in anomaly detection: {e}")


class PacketProcessor:
    """Handles packet processing and token extraction"""
    
    def __init__(self, session_tracker: SessionTracker):
        self.session_tracker = session_tracker
    
    def extract_token_info(self, packet) -> Tuple[Optional[str], Optional[str], Optional[str]]:
        """Extract token information from packet with error handling"""
        try:
            if not packet.haslayer(Raw):
                return None, None, None
            
            payload = packet[Raw].load
            src_ip = packet[1].src
            
            # Extract User-Agent
            user_agent_match = re.search(rb"User-Agent: (.*?)\r\n", payload)
            user_agent = user_agent_match.group(1).decode(errors='ignore') if user_agent_match else "Unknown"
            
            # Extract tokens
            for pattern in TOKEN_PATTERNS:
                match = pattern.search(payload)
                if match:
                    token = match.group(0).decode(errors='ignore')
                    return src_ip, token.strip(), user_agent
            
            return None, None, None
        except Exception as e:
            logger.debug(f"Error extracting token info: {e}")
            return None, None, None

    def process_packet(self, packet) -> None:
        """Process individual packet with comprehensive error handling"""
        try:
            # Handle HTTP requests
            if packet.haslayer(HTTPRequest):
                self._handle_http_request(packet)
            
            # Handle TCP packets with raw data
            if packet.haslayer(TCP) and packet.haslayer(Raw):
                src_ip, token, user_agent = self.extract_token_info(packet)
                if token:
                    self.session_tracker.detect_anomaly(src_ip, token, user_agent)
                
        except Exception as e:
            logger.error(f"Error processing packet: {e}")
    
    def _handle_http_request(self, packet) -> None:
        """Handle HTTP request packets"""
        try:
            method = packet[HTTPRequest].Method.decode()
            host = packet[HTTPRequest].Host.decode()
            path = packet[HTTPRequest].Path.decode()
            
            log_line = f"[{datetime.now()}] {method} http://{host}{path}"
            print(log_line)
            
            self.session_tracker.log_event({
                "type": "http_request",
                "timestamp": datetime.now().isoformat(),
                "method": method,
                "host": host,
                "path": path
            })
        except Exception as e:
            logger.error(f"Error handling HTTP request: {e}")


class NetworkMonitor:
    """Manages network monitoring and packet capture"""
    
    def __init__(self, interface: str, session_tracker: SessionTracker):
        self.interface = interface
        self.session_tracker = session_tracker
        self.packet_processor = PacketProcessor(session_tracker)
        self.sniff_thread: Optional[threading.Thread] = None
    
    def start_monitoring(self) -> None:
        """Start network monitoring in a separate thread"""
        try:
            self.sniff_thread = threading.Thread(
                target=self._sniff_packets,
                daemon=True
            )
            self.sniff_thread.start()
            logger.info(f"Started monitoring interface: {self.interface}")
        except Exception as e:
            logger.error(f"Failed to start monitoring: {e}")
            raise XRayAuthError(f"Failed to start monitoring: {e}")
    
    def _sniff_packets(self) -> None:
        """Sniff packets with error handling"""
        try:
            sniff(
                iface=self.interface,
                filter="tcp port 80",
                prn=self.packet_processor.process_packet,
                store=0,
                stop_filter=lambda pkt: stop_event.is_set()
            )
        except Exception as e:
            logger.error(f"Packet sniffing error: {e}")
            if not stop_event.is_set():
                raise XRayAuthError(f"Packet sniffing failed: {e}")
    
    def stop_monitoring(self) -> None:
        """Stop network monitoring"""
        stop_event.set()
        if self.sniff_thread and self.sniff_thread.is_alive():
            self.sniff_thread.join(timeout=5)
            logger.info("Network monitoring stopped")


def signal_handler(signum, frame):
    """Handle interrupt signals gracefully"""
    logger.info("Received interrupt signal, shutting down...")
    stop_event.set()
    sys.exit(0)


def print_banner():
    """Print application banner"""
    print("=" * 60)
    print("🛡️  XRayAuth - Session Hijack Detection Tool")
    print("📦  Version: 1.0.0 (Optimized)")
    print("👤  Author: Akki")
    print("🔧  Optimized with improved exception handling")
    print("=" * 60)


def validate_interface(interface: str) -> bool:
    """Validate network interface exists"""
    try:
        import subprocess
        result = subprocess.run(['ip', 'link', 'show', interface], 
                              capture_output=True, text=True)
        return result.returncode == 0
    except Exception:
        return False


def main():
    """Main application entry point"""
    try:
        print_banner()
        
        # Check dependencies
        if not SCAPY_AVAILABLE:
            print("[-] Error: Scapy is required but not available.")
            print("[-] Install it with: pip install scapy")
            sys.exit(1)
        
        # Load configuration
        config = ConfigManager.load_config()
        
        # Setup argument parser
        parser = argparse.ArgumentParser(
            description="XRayAuth - Session Hijack Detection Tool",
            formatter_class=argparse.RawDescriptionHelpFormatter,
            epilog="""
Examples:
  xrayauth -i eth0 -l /path/to/log.json
  xrayauth --interface wlan0 --log ~/xrayauth.log
            """
        )
        parser.add_argument(
            "-i", "--interface", 
            default=config.get('interface', 'eth0'),
            help="Network interface to sniff on (default: %(default)s)"
        )
        parser.add_argument(
            "-l", "--log", 
            default=config.get('log', '~/xrayauth_logs.json'),
            help="Log file path (default: %(default)s)"
        )
        parser.add_argument(
            "-v", "--verbose",
            action='store_true',
            help="Enable verbose logging"
        )
        
        args = parser.parse_args()
        
        # Setup logging level
        if args.verbose:
            logging.getLogger().setLevel(logging.DEBUG)
        
        # Validate interface
        if not validate_interface(args.interface):
            logger.error(f"Interface '{args.interface}' not found or not accessible")
            print(f"[-] Error: Interface '{args.interface}' not found.")
            print("[-] Available interfaces:")
            try:
                import subprocess
                result = subprocess.run(['ip', 'link', 'show'], 
                                      capture_output=True, text=True)
                for line in result.stdout.split('\n'):
                    if ':' in line and not line.startswith(' '):
                        iface = line.split(':')[1].strip()
                        print(f"    - {iface}")
            except Exception:
                print("    (Unable to list interfaces)")
            sys.exit(1)
        
        # Ensure log file directory exists
        log_path = os.path.expanduser(args.log)
        os.makedirs(os.path.dirname(log_path), exist_ok=True)
        
        # Initialize components
        session_tracker = SessionTracker(log_path)
        monitor = NetworkMonitor(args.interface, session_tracker)
        
        # Setup signal handlers
        signal.signal(signal.SIGINT, signal_handler)
        signal.signal(signal.SIGTERM, signal_handler)
        
        print(f"[*] Monitoring interface {args.interface} for HTTP traffic...")
        print(f"[*] Logging to: {log_path}")
        print("[*] Press Ctrl+C to stop monitoring\n")
        
        # Start monitoring
        monitor.start_monitoring()
        
        # Wait for stop signal
        try:
            while not stop_event.is_set():
                import time
                time.sleep(1)
    except KeyboardInterrupt:
            logger.info("Received keyboard interrupt")
        finally:
            monitor.stop_monitoring()
            print("\n[*] Monitoring stopped. Goodbye!")
    
    except XRayAuthError as e:
        logger.error(f"XRayAuth error: {e}")
        print(f"[-] Error: {e}")
        sys.exit(1)
    except Exception as e:
        logger.error(f"Unexpected error: {e}")
        print(f"[-] Unexpected error: {e}")
        sys.exit(1)


if __name__ == "__main__":
    main()
