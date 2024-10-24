import requests
import getpass
import json

BASE_URL = "http://localhost:8000/api"
REGISTER_URL = f"{BASE_URL}/register/"

def register_user():
    print("User Registration")
    username = input("Enter username: ")
    email = input("Enter email: ")
    password = getpass.getpass("Enter password: ")
    password2 = getpass.getpass("Confirm password: ")

    data = {
        "username": username,
        "email": email,
        "password": password,
        "password2": password2
    }

    response = requests.post(REGISTER_URL, json=data)

    if response.status_code == 201:
        print("Registration successful!")
        return response.json()
    else:
        print("Registration failed.")
        print(response.json())
        return None

def main():
    result = register_user()
    if result:
        print("User data:", json.dumps(result, indent=2))

if __name__ == "__main__":
    main()