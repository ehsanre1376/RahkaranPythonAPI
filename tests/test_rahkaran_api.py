"""
Tests for the Rahkaran API client.
"""

import pytest
from unittest.mock import Mock, patch
from datetime import datetime, timedelta

from rahkaran_api import RahkaranAPI, RahkaranConfig
from rahkaran_api.exceptions import AuthenticationError, APIError

@pytest.fixture
def config():
    return RahkaranConfig(
        rahkaran_name="test",
        server_name="test.example.com",
        username="test_user",
        password="test_pass"
    )

@pytest.fixture
def api(config):
    return RahkaranAPI(config)

def test_config_validation():
    """Test configuration validation."""
    # Valid config
    config = RahkaranConfig(rahkaran_name="test")
    config.validate()
    
    # Invalid rahkaran_name
    with pytest.raises(ValueError):
        RahkaranConfig(rahkaran_name="").validate()
    
    # Invalid port
    with pytest.raises(ValueError):
        RahkaranConfig(rahkaran_name="test", port="invalid").validate()
    
    # Invalid protocol
    with pytest.raises(ValueError):
        RahkaranConfig(rahkaran_name="test", protocol="ftp").validate()

def test_base_url(config):
    """Test base URL construction."""
    assert config.base_url == "http://test.example.com:80/test"

@patch("requests.Session")
def test_login_success(mock_session, api):
    """Test successful login flow."""
    # Mock session response
    mock_response = Mock()
    mock_response.status_code = 200
    mock_response.json.return_value = {
        "rsa": {
            "M": "00",  # Mock RSA modulus
            "E": "00"   # Mock RSA exponent
        },
        "id": "test_session"
    }
    mock_response.headers = {
        "Set-Cookie": "a,2024-12-31 23:59:59 GMT,session_token"
    }
    
    mock_session.return_value.get.return_value = mock_response
    mock_session.return_value.post.return_value = mock_response
    
    # Test login
    token = api.login()
    assert token == "session_token"

@patch("requests.Session")
def test_login_failure(mock_session, api):
    """Test login failure handling."""
    # Mock failed session response
    mock_response = Mock()
    mock_response.status_code = 401
    mock_response.raise_for_status.side_effect = Exception("Login failed")
    
    mock_session.return_value.get.return_value = mock_response
    
    # Test login failure
    with pytest.raises(AuthenticationError):
        api.login()

@patch("requests.Session")
def test_get_request(mock_session, api):
    """Test GET request."""
    # Mock successful response
    mock_response = Mock()
    mock_response.status_code = 200
    mock_response.json.return_value = {"data": "test"}
    
    mock_session.return_value.get.return_value = mock_response
    
    # Test GET request
    response = api.get("/test/endpoint")
    assert response == {"data": "test"}

@patch("requests.Session")
def test_post_request(mock_session, api):
    """Test POST request."""
    # Mock successful response
    mock_response = Mock()
    mock_response.status_code = 200
    mock_response.json.return_value = {"data": "test"}
    
    mock_session.return_value.post.return_value = mock_response
    
    # Test POST request
    response = api.post("/test/endpoint", {"test": "data"})
    assert response == {"data": "test"} 