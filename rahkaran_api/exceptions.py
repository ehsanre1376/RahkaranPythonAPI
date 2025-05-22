"""
Custom exceptions for the Rahkaran API client.
"""

class RahkaranError(Exception):
    """Base exception for all Rahkaran API errors."""
    pass

class AuthenticationError(RahkaranError):
    """Raised when authentication fails."""
    pass

class APIError(RahkaranError):
    """Raised when the API returns an error response."""
    def __init__(self, message: str, status_code: int = None, response: dict = None):
        super().__init__(message)
        self.status_code = status_code
        self.response = response or {} 