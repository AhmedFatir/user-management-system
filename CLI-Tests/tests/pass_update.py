import requests
import getpass

BASE_URL = "http://localhost:8000/api"
LOGIN_URL = f"{BASE_URL}/login/"
PASSWORD_CHANGE_URL = f"{BASE_URL}/password-change/"

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

def update_password(access_token, old_password, new_password):
    headers = {"Authorization": f"Bearer {access_token}"}
    update_data = {
        "old_password": old_password,
        "new_password": new_password
    }

    response = requests.post(PASSWORD_CHANGE_URL, headers=headers, json=update_data)
    
    if response.status_code == 200:
        print("Password updated successfully!")
        print("Response:", response.json())
    else:
        print("Password update failed.")
        print("Response:", response.text)

def main():
    print("User Login")
    username = input("Enter username: ")
    password = getpass.getpass("Enter current password: ")

    login_result = login(username, password)
    if login_result:
        print("Login successful!")
        access_token = login_result.get('access')
        if access_token:
            print("\nPassword Update")
            old_password = getpass.getpass("Enter your current password again: ")
            new_password = getpass.getpass("Enter new password: ")
            confirm_password = getpass.getpass("Confirm new password: ")
            
            if new_password != confirm_password:
                print("New passwords do not match. Password update cancelled.")
            else:
                update_password(access_token, old_password, new_password)
        else:
            print("No access token received. Cannot proceed with password update.")
    else:
        print("Login failed. Cannot proceed with password update.")

if __name__ == "__main__":
    main()