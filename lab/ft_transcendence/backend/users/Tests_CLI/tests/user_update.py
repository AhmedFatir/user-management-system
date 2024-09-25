import requests
import getpass
import json

BASE_URL = "http://localhost:8000/api"
LOGIN_URL = f"{BASE_URL}/login/"
UPDATE_PROFILE_URL = f"{BASE_URL}/profile-update/"

def login(username, password):
    login_data = {
        "username": username,
        "password": password
    }
    response = requests.post(LOGIN_URL, json=login_data)
    if response.status_code == 200:
        return response.json()
    else:
        print("Login failed.")
        print("Response:", response.text)
        return None

def update_profile(access_token):
    headers = {"Authorization": f"Bearer {access_token}"}
    
    print("\nUpdating Profile")
    print("Leave blank if you don't want to update a field.")
    
    first_name = input("Enter new first name: ")
    last_name = input("Enter new last name: ")
    email = input("Enter new email: ")

    update_data = {}
    if first_name:
        update_data['first_name'] = first_name
    if last_name:
        update_data['last_name'] = last_name
    if email:
        update_data['email'] = email

    if not update_data:
        print("No updates provided.")
        return

    response = requests.put(UPDATE_PROFILE_URL, headers=headers, json=update_data)
    
    if response.status_code == 200:
        print("Profile updated successfully!")
        print("Updated profile:", json.dumps(response.json(), indent=2))
    else:
        print("Profile update failed.")
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
            update_profile(access_token)
        else:
            print("No access token received. Cannot proceed with profile update.")
    else:
        print("Login failed. Cannot proceed with profile update.")

if __name__ == "__main__":
    main()