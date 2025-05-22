import json
import tempfile
import requests
import os
from datetime import datetime, timedelta
import rsa
import binascii
import logging
from logging.handlers import BaseRotatingHandler
from urllib.parse import urlparse
import re
from typing import Optional, Dict, Any, Union



class DailyRotatingFileHandler(BaseRotatingHandler):
    def __init__(self, filename_prefix, backup_days=7):
        self.filename_prefix = filename_prefix
        self.backup_days = backup_days
        self.current_date = datetime.now().date()
        self._cleanup_old_logs()
        super().__init__(self._current_filename(), "a")

    def _current_filename(self):
        return f"{self.filename_prefix}_{self.current_date.strftime('%Y-%m-%d')}.log"

    def _cleanup_old_logs(self):
        cutoff = datetime.now() - timedelta(days=self.backup_days)
        for filename in os.listdir(os.path.dirname(self.filename_prefix) or "."):
            if filename.startswith(os.path.basename(self.filename_prefix)):
                try:
                    file_date = datetime.strptime(filename[-14:-4], "%Y-%m-%d").date()
                    if file_date < cutoff.date():
                        os.remove(
                            os.path.join(
                                os.path.dirname(self.filename_prefix), filename
                            )
                        )
                except ValueError:
                    continue

    def shouldRollover(self, record):
        self.record = record
        return datetime.now().date() != self.current_date

    def doRollover(self):
        if self.stream:
            self.stream.close()
        self.current_date = datetime.now().date()
        self._cleanup_old_logs()
        self.baseFilename = self._current_filename()
        self.stream = self._open()


# Configure logging at the start of your application
logger = logging.getLogger(__name__)
handler = DailyRotatingFileHandler(
    filename_prefix="rahkaran_api",  # Base name for log files
    backup_days=7,  # Delete logs older than 7 days
)
handler.setFormatter(
    logging.Formatter("%(asctime)s - %(name)s - %(levelname)s - %(message)s")
)
logger.addHandler(handler)
logger.setLevel(logging.ERROR)  # Set to ERROR level as per original code

APPLICATION_JSON = "application/json"


class RahkaranAPI:
    def __init__(
        self,
        rahkaran_name: str,
        server_name: str = "localhost",
        port: str = "80",
        username: str = "admin",
        password: str = "admin",
        protocol: str = "http",
        verify_ssl: bool = True,
        timeout: int = 10,
        max_retries: int = 3
    ):
        """
        Initialize the RahkaranAPI client.
        
        Args:
            rahkaran_name: Name of the Rahkaran instance
            server_name: Server hostname
            port: Server port
            username: Authentication username
            password: Authentication password
            protocol: HTTP protocol (http/https)
            verify_ssl: Whether to verify SSL certificates
            timeout: Request timeout in seconds
            max_retries: Maximum number of retry attempts
        """
        # Input validation
        if not rahkaran_name or not isinstance(rahkaran_name, str):
            raise ValueError("rahkaran_name must be a non-empty string")
        
        if not re.match(r'^[a-zA-Z0-9.-]+$', server_name):
            raise ValueError("Invalid server_name format")
            
        if not port.isdigit() or not (1 <= int(port) <= 65535):
            raise ValueError("Port must be a number between 1 and 65535")
            
        if protocol not in ['http', 'https']:
            raise ValueError("Protocol must be either 'http' or 'https'")

        self.server_name = server_name
        self.port = port
        self.username = username
        self.password = password
        self.rahkaran_name = rahkaran_name
        self.protocol = protocol
        self.verify_ssl = verify_ssl
        self.timeout = timeout
        self.max_retries = max_retries
        
        # Session management
        self.session = ""
        self.expire_date = datetime.now() - timedelta(minutes=5)
        self.auth_file = f"sg-auth-{rahkaran_name}.txt"
        
        # Initialize requests session with retry mechanism
        self.http_session = requests.Session()
        if not self.verify_ssl:
            self.http_session.verify = False
            # Disable SSL warning if verification is disabled
            requests.packages.urllib3.disable_warnings()
            
        # Configure retry strategy
        retry_strategy = requests.adapters.Retry(
            total=max_retries,
            backoff_factor=0.5,
            status_forcelist=[500, 502, 503, 504]
        )
        adapter = requests.adapters.HTTPAdapter(max_retries=retry_strategy)
        self.http_session.mount("http://", adapter)
        self.http_session.mount("https://", adapter)

    @property
    def base_url(self):
        return f"{self.protocol}://{self.server_name}:{self.port}/{self.rahkaran_name}"

    def hex_string_to_bytes(self, hex_string):
        try:
            return binascii.unhexlify(hex_string)
        except binascii.Error as e:
            logger.error(f"Hex to bytes conversion error: {e}")
            return None

    def bytes_to_hex_string(self, byte_array):
        try:
            return binascii.hexlify(byte_array).decode()
        except binascii.Error as e:
            logger.error(f"Bytes to hex conversion error: {e}")
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
                                self.expire_date = datetime.strptime(
                                    content[1].strip(), "%d-%b-%Y %H:%M:%S"
                                )
                                
                                # If session is still valid, return it
                                if datetime.now() < self.expire_date:
                                    return self.session
                    else:
                        # Delete old auth file
                        try:
                            os.remove(auth_file_path)
                        except OSError:
                            pass
            except Exception as e:
                logger.warning(f"Error reading auth file: {str(e)}")
        
        # If we get here, we need a new session
        return self._send_request_login()

    def _send_request_login(self) -> Optional[str]:
        """
        Internal method to perform the login request.
        
        Returns:
            Optional[str]: The session token or None if login failed
        """
        url = f"{self.base_url}/Services/Framework/AuthenticationService.svc"
        session_url = f"{url}/session"
        login_url = f"{url}/login"

        try:
            response = self.http_session.get(
                session_url,
                timeout=self.timeout,
                verify=self.verify_ssl
            )
            response.raise_for_status()
            session = response.json()

            m = self.hex_string_to_bytes(session["rsa"]["M"])
            ee = self.hex_string_to_bytes(session["rsa"]["E"])
            if m is None or ee is None:
                logger.error("Failed to decode RSA parameters")
                return None

            rsa_key = rsa.PublicKey(
                int.from_bytes(m, byteorder="big"),
                int.from_bytes(ee, byteorder="big")
            )

            session_id = session["id"]
            session_plus_password = f"{session_id}**{self.password}"
            encrypted_password = rsa.encrypt(session_plus_password.encode(), rsa_key)
            hex_password = self.bytes_to_hex_string(encrypted_password)
            
            if not hex_password:
                logger.error("Failed to encrypt password")
                return None

            headers = {"content-Type": APPLICATION_JSON}
            data = {
                "sessionId": session_id,
                "username": self.username,
                "password": hex_password,
            }

            response = self.http_session.post(
                login_url,
                headers=headers,
                json=data,
                timeout=self.timeout,
                verify=self.verify_ssl
            )
            response.raise_for_status()

            # Parse Set-Cookie header
            set_cookie = response.headers.get("Set-Cookie")
            if not set_cookie:
                logger.error("No Set-Cookie header in response")
                return None

            cookie_parts = set_cookie.split(",")
            if len(cookie_parts) < 3:
                logger.error("Invalid Set-Cookie header format")
                return None

            self.session = cookie_parts[2].split(";")[0].strip()
            expire_str = cookie_parts[1].split(";")[0].strip()
            self.expire_date = datetime.strptime(expire_str, "%d-%b-%Y %H:%M:%S %Z")

            # Save session to temp file
            try:
                auth_file_path = os.path.join(tempfile.gettempdir(), self.auth_file)
                with open(auth_file_path, "w", encoding="utf-8") as f:
                    f.write(f"{self.session}\n")
                    f.write(self.expire_date.strftime("%d-%b-%Y %H:%M:%S"))
                
                # Set file permissions to user-only
                os.chmod(auth_file_path, 0o600)
            except IOError as e:
                logger.warning(f"Failed to write auth file: {str(e)}")

            return self.session

        except requests.exceptions.RequestException as e:
            logger.error(f"Login request failed: {str(e)}")
        except (KeyError, IndexError) as e:
            logger.error(f"Invalid response format: {str(e)}")
        except (ValueError, binascii.Error) as e:
            logger.error(f"Data processing error: {str(e)}")
        except Exception as e:
            logger.error(f"Unexpected error during login: {str(e)}")

        return None

    def _send_get(self, url: str) -> Optional[Dict[str, Any]]:
        """
        Send a GET request to the API.
        
        Args:
            url: The endpoint URL
            
        Returns:
            Optional[Dict[str, Any]]: The JSON response or None if request failed
        """
        try:
            cookie = self.login()
            if not cookie:
                logger.error("No valid session cookie available")
                return None
                
            headers = {"content-Type": APPLICATION_JSON, "Cookie": cookie}
            
            response = self.http_session.get(
                self.base_url + url,
                headers=headers,
                timeout=self.timeout,
                verify=self.verify_ssl
            )
            
            if response.status_code == 401:  # Unauthorized
                logger.info("Session expired, attempting to refresh...")
                retry_cookie = self.login(is_retry=True)
                if not retry_cookie:
                    logger.error("Retry login failed during GET request")
                    return None
                    
                headers["Cookie"] = retry_cookie
                response = self.http_session.get(
                    self.base_url + url,
                    headers=headers,
                    timeout=self.timeout,
                    verify=self.verify_ssl
                )
            
            response.raise_for_status()
            return response.json()
            
        except requests.exceptions.Timeout:
            logger.error(f"Request timed out for GET {url}")
        except requests.exceptions.SSLError:
            logger.error(f"SSL verification failed for GET {url}")
        except requests.exceptions.ConnectionError:
            logger.error(f"Connection failed for GET {url}")
        except requests.exceptions.RequestException as e:
            logger.error(f"Request failed for GET {url}: {str(e)}")
        except json.JSONDecodeError as e:
            logger.error(f"Failed to parse GET response: {str(e)}")
        except Exception as e:
            logger.error(f"Unexpected error during GET {url}: {str(e)}")
        
        return None

    def _send_post(self, url: str, data: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        """
        Send a POST request to the API.
        
        Args:
            url: The endpoint URL
            data: The request payload
            
        Returns:
            Optional[Dict[str, Any]]: The JSON response or None if request failed
        """
        try:
            cookie = self.login()
            if not cookie:
                logger.error("No valid session cookie available")
                return None
                
            headers = {"content-Type": APPLICATION_JSON, "Cookie": cookie}
            
            response = self.http_session.post(
                self.base_url + url,
                headers=headers,
                json=data,  # Use json parameter instead of manually dumping
                timeout=self.timeout,
                verify=self.verify_ssl
            )
            
            if response.status_code == 401:  # Unauthorized
                logger.info("Session expired, attempting to refresh...")
                retry_cookie = self.login(is_retry=True)
                if not retry_cookie:
                    logger.error("Retry login failed during POST request")
                    return None
                    
                headers["Cookie"] = retry_cookie
                response = self.http_session.post(
                    self.base_url + url,
                    headers=headers,
                    json=data,
                    timeout=self.timeout,
                    verify=self.verify_ssl
                )
            
            response.raise_for_status()
            return response.json()
            
        except requests.exceptions.Timeout:
            logger.error(f"Request timed out for POST {url}")
        except requests.exceptions.SSLError:
            logger.error(f"SSL verification failed for POST {url}")
        except requests.exceptions.ConnectionError:
            logger.error(f"Connection failed for POST {url}")
        except requests.exceptions.RequestException as e:
            logger.error(f"Request failed for POST {url}: {str(e)}")
        except json.JSONDecodeError as e:
            logger.error(f"Failed to parse POST response: {str(e)}")
        except Exception as e:
            logger.error(f"Unexpected error during POST {url}: {str(e)}")
        
        return None


r = RahkaranAPI("DEV")

print(
    r._send_get(
        "/General/AddressManagement/Services/AddressManagementWebService.svc/GetRegionalDivisionList"
    )
)
data = [{"Type ": 1, "FirstName": "Ehsan", "LastName": "Rezaei"}]
print(
    r._send_post(
        "/General/PartyManagement/Services/PartyService.svc/GenerateParty",
        data,
    )
)
