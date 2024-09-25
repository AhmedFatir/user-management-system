import requests
import getpass
import time

BASE_URL = "http://localhost:8000/api"
LOGIN_URL = f"{BASE_URL}/login/"
DELETE_URL = f"{BASE_URL}/delete-account/"

def login(username, password):
    login_data = {
        "username": username,
        "password": password
    }
    response = requests.post(f"{LOGIN_URL}", json=login_data)
    if response.status_code == 200:
        return response.json()
    else:
        print("Login failed.")
        print("Response:", response.text)
        return None

def delete_account(access_token):
    headers = {"Authorization": f"Bearer {access_token}"}
    
    print("\nACCOUNT DELETION")
    print("Warning: This action is irreversible. All your data will be permanently deleted.")
    confirmation = input("Type 'DELETE' to confirm account deletion: ")
    
    if confirmation != "DELETE":
        print("Account deletion cancelled.")
        return

    print("Deleting account...")
    response = requests.delete(f"{DELETE_URL}", headers=headers)
    
    if response.status_code == 204:
        print("Account deleted successfully.")
    else:
        print("Account deletion failed.")
        print("Response:", response.text)

def main():
    print("User Login")
    username = input("Enter username: ")
    password = getpass.getpass("Enter password: ")

    login_result = login(username, password)
    if login_result:
        print("Login successful!")
        access_token = login_result.get('access')
        if access_token:
            delete_account(access_token)
        else:
            print("No access token received. Cannot proceed with account deletion.")
    else:
        print("Login failed. Cannot proceed with account deletion.")

    # Add a delay before exiting to allow reading the final message
    time.sleep(2)

if __name__ == "__main__":
    main()