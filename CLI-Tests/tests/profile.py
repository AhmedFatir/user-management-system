import requests
import os
import json
import getpass

BASE_URL = 'http://localhost:8000/api/'

def login():
    username = input("Enter your username: ")
    password = getpass.getpass("Enter your password: ")
    response = requests.post(f'{BASE_URL}login/', json={'username': username, 'password': password})
    if response.status_code == 200:
        return response.json()
    else:
        print("Login failed. Please try again.")
        return None

def avatar_update_test(token):
    image_path = input("Enter the path to the new avatar image: ")
    if not os.path.exists(image_path):
        print("File does not exist. Please provide a valid file path.")
        return

    with open(image_path, 'rb') as image_file:
        files = {'avatar': image_file}
        headers = {'Authorization': f'Bearer {token}'}
        response = requests.post(f'{BASE_URL}upload-avatar/', files=files, headers=headers)

    if response.status_code == 200:
        print("Avatar updated successfully!")
        print(json.dumps(response.json(), indent=2))
    else:
        print(f"Failed to update avatar. Status code: {response.status_code}")
        print(response.text)

def update_profile(token):
    headers = {"Authorization": f"Bearer {token}"}
    
    print("\nUpdating Profile")
    print("Leave blank if you don't want to update a field.")
    
    username = input("Enter new username: ")
    email = input("Enter new email: ")
    first_name = input("Enter new first name: ")
    last_name = input("Enter new last name: ")

    update_data = {}
    if username:
        update_data['username'] = username
    if email:
        update_data['email'] = email
    if first_name:
        update_data['first_name'] = first_name
    if last_name:
        update_data['last_name'] = last_name

    if not update_data:
        print("No updates provided.")
        return

    response = requests.put(f'{BASE_URL}profile-update/', headers=headers, json=update_data)
    
    if response.status_code == 200:
        print("Profile updated successfully!")
        print("Updated profile:", json.dumps(response.json(), indent=2))
    else:
        print("Profile update failed.")
        print("Response:", response.text)

def main():
    login_result = login()
    if not login_result:
        return

    token = login_result['access']

    while True:
        choice = input("\n1. Avatar update\n2. Profile update\nq. Quit\nEnter your choice: ")

        if choice == '1':
            avatar_update_test(token)
        elif choice == '2':
            update_profile(token)
        elif choice.lower() == 'q':
            break
        else:
            print("Invalid choice. Please try again.")

if __name__ == "__main__":
    main()