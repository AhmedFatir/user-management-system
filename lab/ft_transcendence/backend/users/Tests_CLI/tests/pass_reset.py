import requests, getpass

BASE_URL = "http://localhost:8000/api"
LOGIN_URL = f"{BASE_URL}/login/"
PASSWORD_RESET_URL = f"{BASE_URL}/password-reset/"
PASSWORD_CHANGE_URL = f"{BASE_URL}/password-change/"

def reset_password():
    email = input("Enter your email address: ")

    # Request password reset
    response = requests.post(PASSWORD_RESET_URL, json={"email": email})
    
    if response.status_code == 200:
        print("A temporary password has been sent to your email.")
        print("Please check your email and use the temporary password to log in.")
        
        # Prompt user to log in with temporary password
        username = input("Enter your username: ")
        temp_password = getpass.getpass("Enter the temporary password: ")
        
        # Attempt to log in
        login_response = requests.post(LOGIN_URL, json={"username": username, "password": temp_password})
        
        if login_response.status_code == 200:
            print("Login successful. You can now change your password.")
            
            # Prompt user to change password
            new_password = getpass.getpass("Enter your new password: ")
            confirm_password = getpass.getpass("Confirm your new password: ")
            
            if new_password == confirm_password:
                # Get the access token from the login response
                access_token = login_response.json()['access']
                
                # Change password
                headers = {'Authorization': f'Bearer {access_token}'}
                change_password_response = requests.post(
                    PASSWORD_CHANGE_URL,
                    json={"old_password": temp_password, "new_password": new_password},
                    headers=headers
                )
                
                if change_password_response.status_code == 200:
                    print("Password changed successfully.")
                else:
                    print("Failed to change password. Please try again later.")
            else:
                print("Passwords do not match. Please start the process again.")
        else:
            print("Login failed. Please check your temporary password and try again.")
    else:
        print("Password reset failed. Please check your email and try again.")

if __name__ == "__main__":
    reset_password()