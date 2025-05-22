"""
Configuration management for the Rahkaran API client.
"""

from dataclasses import dataclass
from typing import Optional
import logging

@dataclass
class RahkaranConfig:
    """Configuration class for RahkaranAPI client."""
    rahkaran_name: str
    server_name: str = "localhost"
    port: str = "80"
    username: str = "admin"
    password: str = "admin"
    protocol: str = "http"
    verify_ssl: bool = True
    timeout: int = 10
    max_retries: int = 3
    log_level: int = logging.ERROR
    backup_days: int = 7
    
    @property
    def base_url(self) -> str:
        """Get the base URL for API requests."""
        return f"{self.protocol}://{self.server_name}:{self.port}/{self.rahkaran_name}"
    
    def validate(self) -> None:
        """Validate the configuration values."""
        if not self.rahkaran_name:
            raise ValueError("rahkaran_name must not be empty")
        
        if not isinstance(self.port, str) or not self.port.isdigit():
            raise ValueError("port must be a string containing digits")
            
        port_num = int(self.port)
        if not (1 <= port_num <= 65535):
            raise ValueError("port must be between 1 and 65535")
            
        if self.protocol not in ['http', 'https']:
            raise ValueError("protocol must be either 'http' or 'https'")
            
        if self.timeout <= 0:
            raise ValueError("timeout must be positive")
            
        if self.max_retries < 0:
            raise ValueError("max_retries must not be negative")
            
        if self.backup_days < 1:
            raise ValueError("backup_days must be at least 1") 