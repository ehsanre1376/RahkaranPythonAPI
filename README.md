# Rahkaran API Client

A Python client library for interacting with the Rahkaran API.

## Installation

```bash
pip install rahkaran-api
```

## Quick Start

```python
from rahkaran_api import RahkaranAPI

# Initialize the client
client = RahkaranAPI(
    rahkaran_name="YOUR_RAHKARAN_NAME",
    server_name="your-server.com",
    username="your-username",
    password="your-password"
)

# Make GET request
response = client._send_get("/your/endpoint/path")

# Make POST request
data = {"key": "value"}
response = client._send_post("/your/endpoint/path", data)
```

## Features

- Secure authentication with RSA encryption
- Automatic session management
- Connection pooling and retry mechanism
- Configurable SSL verification
- Comprehensive error handling
- Automatic rate limiting
- Request timeout configuration

## Development

To set up the development environment:

```bash
# Clone the repository
git clone https://github.com/yourusername/rahkaran-api.git
cd rahkaran-api

# Create a virtual environment
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate

# Install development dependencies
pip install -e ".[dev]"
```

## Running Tests

```bash
pytest tests/
```

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

## License

This project is licensed under the MIT License - see the LICENSE file for details.