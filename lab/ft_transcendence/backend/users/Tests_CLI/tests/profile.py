import requests
import os
import json
import getpass

BASE_URL = 'http://localhost:8000/api/'  # Adjust this if your API is hosted elsewhere

def login():
    username = input("Enter your username: ")
    password = getpass.getpass("Enter your password: ")
    response = requests.post(f'{BASE_URL}login/', json={'username': username, 'password': password})
    if response.status_code == 200:
        return response.json()['access']
    else:
        print("Login failed. Please try again.")
        return None

def avatar_update_test():
    token = login()
    if not token:
        return

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

def friend_test():
    token = login()
    if not token:
        return

    headers = {'Authorization': f'Bearer {token}'}

    while True:
        print("1. Send a friend request \n2. View friend list \nq. to quit")
        choice = input("Enter (1 or 2): ")

        if choice == '1':
            username = input("Enter the username of the friend you want to add: ")
            response = requests.post(f'{BASE_URL}send-friend-request/', json={'username': username}, headers=headers)
            if response.status_code == 200:
                print("Friend request sent successfully!")
            else:
                print(f"Failed to send friend request. Status code: {response.status_code}")
                print(response.text)

        elif choice == '2':
            response = requests.get(f'{BASE_URL}friends/', headers=headers)
            if response.status_code == 200:
                friends = response.json()
                print("Your friends:")
                for friend in friends:
                    print(f"- {friend['username']} (Online: {'Yes' if friend['is_online'] else 'No'})")
            else:
                print(f"Failed to retrieve friend list. Status code: {response.status_code}")
                print(response.text)

        elif choice.lower() == 'q':
            break

        else:
            print("Invalid choice. Please try again.")

if __name__ == "__main__":

    print ("1. avatar update \n2. friend test")
    test_choice = input("Enter (1 or 2): ")
    if test_choice == '1':
        avatar_update_test()
    elif test_choice == '2':
        friend_test()
    else:
        print("Invalid choice. Exiting.")