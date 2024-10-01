import requests
import json
import getpass
import sys, os

BASE_URL = "http://localhost:8000/api/"
LOGIN_URL = f"{BASE_URL}login/"
VIEW_PROFILE_URL = f"{BASE_URL}users/me/"
EDIT_PROFILE_URL = f"{BASE_URL}profile-update/"
EDIT_AVATAR_URL = f"{BASE_URL}upload-avatar/"
DELETE_ACCOUNT_URL = f"{BASE_URL}delete-account/"
ANONYMIZE_DATA_URL = f"{BASE_URL}anonymize-data/"
DASHBOARD_URL = f"{BASE_URL}gdpr-dashboard/"

def get_input(prompt):
	return input(prompt).strip()

def login():
	username = get_input("Enter your username: ")
	password = getpass.getpass("Enter your password: ")

	response = requests.post(LOGIN_URL, json={
		"username": username,
		"password": password
	})
	
	if response.status_code == 200:
		return username, response.json()['access']
	else:
		print("Login failed. Please try again.")
		sys.exit(1)

def get_gdpr_options(username):
	return {
		"1": ("gdpr_dashboard"),
		"2": ("view_profile"),
		"3": ("edit_profile"),
		"4": ("change_avatar"),
		"5": ("anonymize_data"),
		"5": ("privacy_policy"),
		"7": ("delete_account")
	}

def delete_account(access_token):
	headers = {"Authorization": f"Bearer {access_token}"}
	
	print("\nACCOUNT DELETION")
	print("Warning: This action is irreversible. All your data will be permanently deleted.")
	confirmation = input("Type 'DELETE' to confirm account deletion: ")
	
	if confirmation != "DELETE":
		print("Account deletion cancelled.")
		return

	print("Deleting account...")
	response = requests.delete(DELETE_ACCOUNT_URL, headers=headers)
	
	if response.status_code == 204:
		print("Account deleted successfully.")
	else:
		print("Account deletion failed.")
		print("Response:", response.text)

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

	response = requests.put(EDIT_PROFILE_URL, headers=headers, json=update_data)
	
	if response.status_code == 200:
		print("Profile updated successfully!")
		print("Updated profile:", json.dumps(response.json(), indent=2))
	else:
		print("Profile update failed.")
		print("Response:", response.text)

def avatar_update_test(token):
	image_path = input("Enter the path to the new avatar image: ")
	if not os.path.exists(image_path):
		print("File does not exist. Please provide a valid file path.")
		return

	try:
		with open(image_path, 'rb') as image_file:
			files = {'avatar': image_file}
			headers = {'Authorization': f'Bearer {token}'}
			response = requests.post(EDIT_AVATAR_URL, files=files, headers=headers)

		if response.status_code == 200:
			print("Avatar updated successfully!")
			print(json.dumps(response.json(), indent=2))
		else:
			print(f"Failed to update avatar. Status code: {response.status_code}")
			print(response.text)
	except IOError:
		print("An error occurred while reading the file. Please check the file and try again.")

def execute_gdpr_action(token, action):
	headers = {"Authorization": f"Bearer {token}"}
	response = None
	print("=====================================================")
	if action == "privacy_policy":
		response = requests.get(DASHBOARD_URL, headers=headers)
		if response.status_code == 200:
			print("Privacy Policy url:", response.json()['privacy_policy'])
		else:
			print("Failed to get privacy policy url.")
		return
	if action == "edit_profile":
		update_profile(token)
		return
	elif action == "change_avatar":
		avatar_update_test(token)
		return
	elif action == "delete_account":
		delete_account(token)
		return

	elif action == "anonymize_data":
		response = requests.post(ANONYMIZE_DATA_URL, headers=headers)
	elif action == "gdpr_dashboard":
		response = requests.get(DASHBOARD_URL, headers=headers)
	elif action == "view_profile":
		response = requests.get(VIEW_PROFILE_URL, headers=headers)

	if response.status_code == 200:
		print("Response:", json.dumps(response.json(), indent=2))
	else:
		print(f"Action {action} failed. Status code: {response.status_code}")
		print("Response:", response.text)

def main():
	print("Welcome to the GDPR CLI Test")
	username, token = login()
	print("Login successful!")
	
	gdpr_options = get_gdpr_options(username)
	
	while True:
		print("=====================================================")
		print("\nAvailable GDPR actions:")
		for key, (action) in gdpr_options.items():
			print(f"{key}. {action}")
		
		choice = get_input("\nEnter the number of the action you want to perform (or 'q' to quit): ")
		
		if choice.lower() == 'q':
			break
		
		if choice in gdpr_options:
			action = gdpr_options[choice]
			execute_gdpr_action(token, action)
		else:
			print(f"Invalid choice. Please enter a number between 1 and {len(gdpr_options)}.")
	
	print("Thank you for using the GDPR CLI Test. Goodbye!")

if __name__ == "__main__":
	main()