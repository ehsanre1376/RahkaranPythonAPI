# Rahkaran API Client

A Python client library for interacting with the Rahkaran API.

## Installation

```bash
pip install RahkaranPythonAPI
```

## Quick Start

```python
import json
from rahkaran_api import RahkaranAPI, RahkaranConfig

# Create config object
config = RahkaranConfig(
    rahkaran_name="code",
    server_name="localhost",
    port="80",
    username="admin",
    password="admin"
)

# Initialize the client with config
client = RahkaranAPI(config)



# Make GET request for demonstration
try:
    response = client.get(
        "/General/AddressManagement/Services/AddressManagementWebService.svc/GetRegionalDivisionList"
    )
    print(json.dumps(response, ensure_ascii=False, indent=2))    
except Exception as e:
    print(f"Error occurred: {str(e)}")

# Data for creating a party
data = [{"Type ": 1, "FirstName": "Ehsan", "LastName": "Rezaei"}]
# Make Post request
try:
    response = client.post(
        "/General/PartyManagement/Services/PartyService.svc/GenerateParty",
        data
        )
    print(json.dumps(response, ensure_ascii=False, indent=2))    
except Exception as e:
    print(f"Error occurred: {str(e)}")

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
