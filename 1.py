import sys
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

# Data for creating a party


# Make GET request for demonstration
try:
    response = client.get(
        "/General/AddressManagement/Services/AddressManagementWebService.svc/GetRegionalDivisionList"
    )
    
    # Print the response with proper encoding handling
    if response:
        # First try using sys.stdout directly
        try:
            print(json.dumps(response, ensure_ascii=False, indent=2))
        except UnicodeEncodeError:
            # If that fails, try forcing UTF-8 encoding
            try:
                encoded = json.dumps(response, ensure_ascii=False, indent=2).encode('utf-8')
                sys.stdout.buffer.write(encoded)
                sys.stdout.buffer.write(b'\n')
            except Exception as e:
                # If all else fails, print with ASCII fallback
                print(json.dumps(response, ensure_ascii=True, indent=2))
                print("\nNote: Some Unicode characters were escaped due to console limitations")
    else:
        print("No response received")
        
except Exception as e:
    print(f"Error occurred: {str(e)}")