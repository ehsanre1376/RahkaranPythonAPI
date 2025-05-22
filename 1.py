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
try:
    response = client.post(
        "/General/PartyManagement/Services/PartyService.svc/GenerateParty",
        data
        )
    print(json.dumps(response, ensure_ascii=False, indent=2))    
except Exception as e:
    print(f"Error occurred: {str(e)}")
