"""
Main client implementation for the Rahkaran API.
"""

import json
import tempfile
import requests
import os
from datetime import datetime, timedelta
import rsa
import binascii
import logging
from logging.handlers import BaseRotatingHandler
from typing import Optional, Dict, Any, Union
from functools import wraps

from .config import RahkaranConfig
from .exceptions import RahkaranError, AuthenticationError, APIError

class DailyRotatingFileHandler(BaseRotatingHandler):
    """A handler that rotates log files daily."""
    
    def __init__(self, filename_prefix: str, backup_days: int = 7):
        self.filename_prefix = filename_prefix
        self.backup_days = backup_days
        self.current_date = datetime.now().date()
        self._cleanup_old_logs()
        super().__init__(self._current_filename(), "a")

    def _current_filename(self) -> str:
        return f"{self.filename_prefix}_{self.current_date.strftime('%Y-%m-%d')}.log"

    def _cleanup_old_logs(self) -> None:
        cutoff = datetime.now() - timedelta(days=self.backup_days)
        log_dir = os.path.dirname(self.filename_prefix) or "."
        prefix_base = os.path.basename(self.filename_prefix)
        
        for filename in os.listdir(log_dir):
            if filename.startswith(prefix_base):
                try:
                    file_date = datetime.strptime(filename[-14:-4], "%Y-%m-%d").date()
                    if file_date < cutoff.date():
                        os.remove(os.path.join(log_dir, filename))
                except ValueError:
                    continue

    def shouldRollover(self, record: logging.LogRecord) -> bool:
        return datetime.now().date() != self.current_date

    def doRollover(self) -> None:
        if self.stream:
            self.stream.close()
        self.current_date = datetime.now().date()
        self._cleanup_old_logs()
        self.baseFilename = self._current_filename()
        self.stream = self._open()

def setup_logging(config: RahkaranConfig) -> None:
    """Set up logging configuration."""
    logger = logging.getLogger(__name__)
    handler = DailyRotatingFileHandler(
        filename_prefix="rahkaran_api",
        backup_days=config.backup_days,
    )
    handler.setFormatter(
        logging.Formatter("%(asctime)s - %(name)s - %(levelname)s - %(message)s")
    )
    logger.addHandler(handler)
    logger.setLevel(config.log_level)
    return logger

def require_auth(func):
    """Decorator to ensure valid authentication before making requests."""
    @wraps(func)
    def wrapper(self, *args, **kwargs):
        if  not self.login():
            if  not self.login(is_retry=True):
                raise AuthenticationError("Failed to authenticate with the API")
        return func(self, *args, **kwargs)
    return wrapper

class RahkaranAPI:
    """Main client class for interacting with the Rahkaran API."""
    
    def __init__(self, config: Union[RahkaranConfig, str], **kwargs):
        """
        Initialize the RahkaranAPI client.
        
        Args:
            config: Either a RahkaranConfig instance or rahkaran_name string
            **kwargs: Additional configuration parameters if config is a string
        """
        if isinstance(config, str):
            self.config = RahkaranConfig(rahkaran_name=config, **kwargs)
        else:
            self.config = config
            
        self.config.validate()
        self.logger = setup_logging(self.config)
        
        # Initialize session management
        self.session = ""
        self.expire_date = datetime.now() - timedelta(minutes=50000)
        self.auth_file = f"sg-auth-{self.config.rahkaran_name}.txt"
        
        # Initialize requests session
        self.http_session = requests.Session()
        if not self.config.verify_ssl:
            self.http_session.verify = False
            requests.packages.urllib3.disable_warnings()
            
        # Configure retry strategy
        retry_strategy = requests.adapters.Retry(
            total=self.config.max_retries,
            backoff_factor=0.5,
            status_forcelist=[500, 502, 503, 504]
        )
        adapter = requests.adapters.HTTPAdapter(max_retries=retry_strategy)
        self.http_session.mount("http://", adapter)
        self.http_session.mount("https://", adapter)

    def hex_string_to_bytes(self, hex_string: str) -> Optional[bytes]:
        """Convert a hex string to bytes."""
        try:
            return binascii.unhexlify(hex_string)
        except binascii.Error as e:
            self.logger.error(f"Hex to bytes conversion error: {e}")
            return None

    def bytes_to_hex_string(self, byte_array: bytes) -> str:
        """Convert bytes to a hex string."""
        try:
            return binascii.hexlify(byte_array).decode()
        except binascii.Error as e:
            self.logger.error(f"Bytes to hex conversion error: {e}")
            return ""

    def login(self, is_retry: bool = False) -> Optional[str]:
        """
        Authenticate with the API and get a session token.
        
        Args:
            is_retry: Whether this is a retry attempt
            
        Returns:
            Optional[str]: The session token or None if authentication failed
        """
        if is_retry:
            return self._send_request_login()
            
        # Check if we have a valid cached session
        if self.expire_date > datetime.now():
            return self.session
            
        # Try to load session from temp file
        if not is_retry:
            try:
                auth_file_path = os.path.join(tempfile.gettempdir(), self.auth_file)
                if os.path.exists(auth_file_path):
                    file_stat = os.stat(auth_file_path)
                    file_age = datetime.now().timestamp() - file_stat.st_mtime
                    
                    # Only read file if it's less than 24 hours old
                    if file_age < 86400:  # 24 hours in seconds
                        with open(auth_file_path, "r", encoding="utf-8") as file:
                            content = file.readlines()
                            if len(content) >= 2:
                                self.session = content[0].strip()
                                expire_str = content[1].strip()
                                try:
                                    # Try parsing with various formats
                                    formats = [
                                        "%d-%b-%Y %H:%M:%S GMT",
                                        "%d-%b-%Y %H:%M:%S",
                                        "%Y-%m-%d %H:%M:%S"
                                    ]
                                    for fmt in formats:
                                        try:
                                            self.expire_date = datetime.strptime(expire_str, fmt)
                                            break
                                        except ValueError:
                                            continue
                                    else:
                                        raise ValueError(f"Could not parse date: {expire_str}")
                                        
                                    # If session is still valid, return it
                                    now_time=datetime.now()
                                    file_time=self.expire_date
                                    if datetime.now() < self.expire_date:
                                        return self.session
                                except ValueError as e:
                                    self.logger.warning(f"Failed to parse stored date: {e}")
                    else:
                        # Delete old auth file
                        try:
                            os.remove(auth_file_path)
                        except OSError:
                            pass
            except Exception as e:
                self.logger.warning(f"Error reading auth file: {str(e)}")
        
        # If we get here, we need a new session
        return self._send_request_login()

    def _send_request_login(self) -> Optional[str]:
        """
        Internal method to perform the login request.
        
        Returns:
            Optional[str]: The session token or None if login failed
        """
        url = f"{self.config.base_url}/Services/Framework/AuthenticationService.svc"
        session_url = f"{url}/session"
        login_url = f"{url}/login"

        try:
            response = self.http_session.get(
                session_url,
                timeout=self.config.timeout,
                verify=self.config.verify_ssl
            )
            response.raise_for_status()
            session = response.json()

            m = self.hex_string_to_bytes(session["rsa"]["M"])
            ee = self.hex_string_to_bytes(session["rsa"]["E"])
            if m is None or ee is None:
                self.logger.error("Failed to decode RSA parameters")
                return None

            rsa_key = rsa.PublicKey(
                int.from_bytes(m, byteorder="big"),
                int.from_bytes(ee, byteorder="big")
            )

            session_id = session["id"]
            session_plus_password = f"{session_id}**{self.config.password}"
            encrypted_password = rsa.encrypt(session_plus_password.encode(), rsa_key)
            hex_password = self.bytes_to_hex_string(encrypted_password)
            
            if not hex_password:
                self.logger.error("Failed to encrypt password")
                return None

            headers = {"content-Type": "application/json"}
            data = {
                "sessionId": session_id,
                "username": self.config.username,
                "password": hex_password,
            }

            response = self.http_session.post(
                login_url,
                headers=headers,
                json=data,
                timeout=self.config.timeout,
                verify=self.config.verify_ssl
            )
            response.raise_for_status()

            # Parse Set-Cookie header
            set_cookie = response.headers.get("Set-Cookie")
            if not set_cookie:
                self.logger.error("No Set-Cookie header in response")
                return None

            cookie_parts = set_cookie.split(",")
            if len(cookie_parts) < 3:
                self.logger.error("Invalid Set-Cookie header format")
                return None

            self.session = cookie_parts[2].split(";")[0].strip()
            expire_str = cookie_parts[1].split(";")[0].strip()
            
            # Remove GMT from string before parsing
            expire_str = expire_str.replace(" GMT", "")
            
            try:
                #pass
                self.expire_date = datetime.strptime(expire_str, "%d-%b-%Y %H:%M:%S")
                
                
            except ValueError as e:
                pass
            try:
                #pass
                
                auth_file_path = os.path.join(tempfile.gettempdir(), self.auth_file)
                
            except ValueError as e:
                pass


            # Save session to temp file
            try:
                
                with open(auth_file_path, "w", encoding="utf-8") as f:
                    f.write(f"{self.session}\n")
                    # Store without timezone for consistency
                    f.write(self.expire_date.strftime("%d-%b-%Y %H:%M:%S"))
                
                # Set file permissions to user-only
                #os.chmod(auth_file_path, 0o600)
            except IOError as e:
                self.logger.warning(f"Failed to write auth file: {str(e)}")

            return self.session

        except requests.exceptions.RequestException as e:
            self.logger.error(f"Login request failed: {str(e)}")
            raise AuthenticationError(f"Login request failed: {str(e)}")
        except (KeyError, IndexError) as e:
            self.logger.error(f"Invalid response format: {str(e)}")
            raise AuthenticationError(f"Invalid response format: {str(e)}")
        except (ValueError, binascii.Error) as e:
            self.logger.error(f"Data processing error: {str(e)}")
            raise AuthenticationError(f"Data processing error: {str(e)}")
        except Exception as e:
            self.logger.error(f"Unexpected error during login: {str(e)}")
            raise AuthenticationError(f"Unexpected error during login: {str(e)}")

    @require_auth
    def get(self, endpoint: str) -> Dict[str, Any]:
        """
        Send a GET request to the API.
        
        Args:
            endpoint: The API endpoint to call
            
        Returns:
            Dict[str, Any]: The JSON response
            
        Raises:
            AuthenticationError: If authentication fails
            APIError: If the API returns an error response
        """
        try:
            headers = {
                "content-Type": "application/json",
                "Cookie": self.session
            }
            
            response = self.http_session.get(
                f"{self.config.base_url}{endpoint}",
                headers=headers,
                timeout=self.config.timeout,
                verify=self.config.verify_ssl
            )
            
            if response.status_code == 401:
                self.login(is_retry=True)
                headers["Cookie"] = self.session
                response = self.http_session.get(
                    f"{self.config.base_url}{endpoint}",
                    headers=headers,
                    timeout=self.config.timeout,
                    verify=self.config.verify_ssl
                )
            
            response.raise_for_status()
            return response.json()
            
        except requests.exceptions.RequestException as e:
            self.logger.error(f"GET request failed for {endpoint}: {str(e)}")
            self.login(is_retry=True)
            self.get(endpoint)
            # raise APIError(f"GET request failed: {str(e)}", 
            #              getattr(response, 'status_code', None),
            #              getattr(response, 'json', lambda: {})())

    @require_auth
    def post(self, endpoint: str, data: Dict[str, Any]) -> Dict[str, Any]:
        """
        Send a POST request to the API.
        
        Args:
            endpoint: The API endpoint to call
            data: The request payload
            
        Returns:
            Dict[str, Any]: The JSON response
            
        Raises:
            AuthenticationError: If authentication fails
            APIError: If the API returns an error response
        """
        try:
            headers = {
                "content-Type": "application/json",
                "Cookie": self.session
            }
            
            response = self.http_session.post(
                f"{self.config.base_url}{endpoint}",
                headers=headers,
                json=data,
                timeout=self.config.timeout,
                verify=self.config.verify_ssl
            )
            
            if response.status_code == 401:
                self.login(is_retry=True)
                headers["Cookie"] = self.session
                response = self.http_session.post(
                    f"{self.config.base_url}{endpoint}",
                    headers=headers,
                    json=data,
                    timeout=self.config.timeout,
                    verify=self.config.verify_ssl
                )
            
            response.raise_for_status()
            return response.json()
            
        except requests.exceptions.RequestException as e:
            self.logger.error(f"POST request failed for {endpoint}: {str(e)}")
            self.login(is_retry=True)
            self.post(endpoint, data)
            # raise APIError(f"POST request failed: {str(e)}", 
                        #  getattr(response, 'status_code', None),
                        #  getattr(response, 'json', lambda: {})())