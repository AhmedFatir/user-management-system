import requests
import getpass
import json

BASE_URL = 'http://localhost:8000/api'
LOGIN_URL = f'{BASE_URL}/login/'
FRIENDS_URL = f'{BASE_URL}/friends/'
REQUESTS_URL = f'{BASE_URL}/friend-requests/'
REQUEST_URL = f'{BASE_URL}/friend-request/'
CANCEL_URL = f'{BASE_URL}/cancel-friend-request/'
RESPONSE_URL = f'{BASE_URL}/friend-response/'

def login(username, password):
	response = requests.post(LOGIN_URL, json={'username': username, 'password': password})
	if response.status_code == 200:
		return response.json()['access']
	else:
		print("Login failed. Please check your credentials.")
		return None

def get_user_lists(token):
    headers = {'Authorization': f'Bearer {token}'}
    friends_response = requests.get(FRIENDS_URL, headers=headers)
    requests_response = requests.get(REQUESTS_URL, headers=headers)
    
    if friends_response.status_code == 200 and requests_response.status_code == 200:
        friends = friends_response.json()
        friend_requests = requests_response.json()
        return friends, friend_requests['incoming'], friend_requests['outgoing']
    else:
        print("Failed to fetch user lists.")
        return [], [], []


def print_lists(friends, incoming, outgoing):
	print("\n=======================================")
	print("Friends list:")
	for friend in friends:
		print(f"- {friend['username']}")
	
	print("\nIncoming friend requests:")
	for request in incoming:
		print(f"- {request['username']}")
	
	print("\nOutgoing friend requests:")
	for request in outgoing:
		print(f"- {request['username']}")
	print("=======================================")

def send_friend_request(token, user_identifier):
	headers = {'Authorization': f'Bearer {token}'}
	response = requests.post(REQUEST_URL + user_identifier + '/', headers=headers)
	if response.status_code == 201:
		print("Friend request sent successfully.")
	else:
		print(f"Failed to send friend request: {response.json().get('error', 'Unknown error')}")

def cancel_friend_request(token, user_identifier):
	headers = {'Authorization': f'Bearer {token}'}
	response = requests.post(CANCEL_URL + user_identifier + '/', headers=headers)
	if response.status_code == 200:
		print("Friend request cancelled successfully.")
	else:
		print(f"Failed to cancel friend request: {response.json().get('error', 'Unknown error')}")

def respond_to_friend_request(token, user_identifier, action):
	headers = {'Authorization': f'Bearer {token}'}
	response = requests.post(RESPONSE_URL + user_identifier + '/', json={'action': action}, headers=headers)
	if response.status_code == 200:
		print(f"Friend request {action}ed successfully.")
	else:
		print(f"Failed to {action} friend request: {response.json().get('error', 'Unknown error')}")

def main():
	username = input("Enter your username: ")
	password = getpass.getpass("Enter password: ")
	
	token = login(username, password)
	if not token:
		return

	while True:
		print("\nAvailable actions:")
		print("1. Send a friend request")
		print("2. Cancel a friend request")
		print("3. Respond to a friend request")
		print("4. View lists")
		print("5. Quit")

		choice = input("Enter your choice (1-5): ")

		if choice == '1':
			user_identifier = input("Enter the username to send a friend request: ")
			send_friend_request(token, user_identifier)
		elif choice == '2':
			user_identifier = input("Enter the username to cancel the friend request: ")
			cancel_friend_request(token, user_identifier)
		elif choice == '3':
			user_identifier = input("Enter the username of the friend request: ")
			action = input("Enter 'accept' or 'reject': ")
			if action in ['accept', 'reject']:
				respond_to_friend_request(token, user_identifier, action)
			else:
				print("Invalid action. Please enter 'accept' or 'reject'.")
		elif choice == '4':
			pass
		elif choice == '5':
			print("Goodbye!")
			break
		else:
			print("Invalid choice. Please enter a number between 1 and 5.")

		friends, incoming, outgoing = get_user_lists(token)
		print_lists(friends, incoming, outgoing)

if __name__ == "__main__":
	main()