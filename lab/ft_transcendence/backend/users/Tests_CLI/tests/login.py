import requests
import getpass
import json

BASE_URL = "http://localhost:8000/api"
LOGIN_URL = f"{BASE_URL}/login/"

def login_user():
    print("User Login")
    username = input("Enter username: ")
    password = getpass.getpass("Enter password: ")

    data = {
        "username": username,
        "password": password
    }

    response = requests.post(LOGIN_URL, json=data)

    if response.status_code == 200:
        print("Login successful!")
        return response.json()
    else:
        print("Login failed.")
        print(response.json())
        return None

def main():
    result = login_user()
    if result:
        print("Login data:", json.dumps(result, indent=2))

if __name__ == "__main__":
    main()