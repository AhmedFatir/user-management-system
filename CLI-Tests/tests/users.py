import requests
import json
import getpass

BASE_URL = "http://localhost:8000/api"  # Adjust this to your server's address
LOGIN_URL = f"{BASE_URL}/login/"
USER_URL = f"{BASE_URL}/users/"

def login():
    username = input("Enter your username: ")
    password = getpass.getpass("Enter your password: ")
    
    response = requests.post(LOGIN_URL, data={"username": username, "password": password})
    
    if response.status_code == 200:
        return response.json()['access']
    else:
        print("\n=======================================")
        print("Login failed. Error:", response.json())
        print("=======================================")
        return None

def get_all_users(token):
    headers = {"Authorization": f"Bearer {token}"}
    response = requests.get(USER_URL, headers=headers)
    
    if response.status_code == 200:
        return response.json()
    else:
        print("\n=======================================")
        print("Failed to get users. Error:", response.json())
        print("=======================================")
        return None

def get_specific_user(token, username):
    headers = {"Authorization": f"Bearer {token}"}
    response = requests.get(USER_URL + f"{username}/", headers=headers)
    
    if response.status_code == 200:
        return response.json()
    else:
        print("\n=======================================")
        print(f"Failed to get user {username}. Error:", response.json())
        print("=======================================")
        return None

def main():
    token = login()
    if not token:
        return

    while True:
        print("\nChoose an option:")
        print("1. Get all users")
        print("2. Get a specific user")
        print("q. Quit")
        
        choice = input("Enter your choice (1-3): ")
        
        if choice == '1':
            users = get_all_users(token)
            if users:
                print("\n=======================================")
                print(json.dumps(users, indent=2))
                print("=======================================")
        elif choice == '2':
            username = input("Enter the username to look up: ")
            user = get_specific_user(token, username)
            if user:
                print("\n=======================================")
                print(json.dumps(user, indent=2))
                print("=======================================")
        elif choice == 'q':
            print("Exiting...")
            break
        else:
            print("\n=======================================")
            print("Invalid choice. Please try again.")
            print("=======================================")

if __name__ == "__main__":
    main()