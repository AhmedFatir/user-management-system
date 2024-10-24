import requests
import getpass, json

BASE_URL = "http://localhost:8000/api"
LOGIN_URL = f"{BASE_URL}/login/"
LOGOUT_URL = f"{BASE_URL}/logout/"

def login_and_logout():
    print("User Login")
    username = input("Enter username: ")
    password = getpass.getpass("Enter password: ")

    # Login
    login_data = {
        "username": username,
        "password": password
    }

    login_response = requests.post(LOGIN_URL, json=login_data)

    if login_response.status_code == 200:
        print("Login successful!")
        login_result = login_response.json()
        print("Login response:", json.dumps(login_result, indent=2))
        
        access_token = login_result.get('access')
        refresh_token = login_result.get('refresh')
        
        if access_token and refresh_token:
            # Logout
            print("\nAttempting to logout...")
            logout_data = {"refresh_token": refresh_token}
            headers = {"Authorization": f"Bearer {access_token}"}
            logout_response = requests.post(LOGOUT_URL, json=logout_data, headers=headers)
            
            if logout_response.status_code == 200:
                print("Logout successful!")
                print("Logout response:", json.dumps(logout_response.json(), indent=2))
            else:
                print("Logout failed.")
                print("Logout response:", logout_response.text)
        else:
            print("No access or refresh token received. Cannot proceed with logout.")
    else:
        print("Login failed.")
        print("Login response:", login_response.text)

if __name__ == "__main__":
    login_and_logout()