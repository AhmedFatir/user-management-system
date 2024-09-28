import requests
import webbrowser
import sys
from urllib.parse import urlparse, parse_qs
import time, os

# Configuration
CLIENT_ID = os.environ.get('UID_INTRA')
CLIENT_SECRET = os.environ.get('SECRET_INTRA')
REDIRECT_URI = 'http://localhost:8000/api/complete/intra42/'
AUTH_URL = 'https://api.intra.42.fr/oauth/authorize'
TOKEN_URL = 'https://api.intra.42.fr/oauth/token'
BASE_URL = 'http://localhost:8000'

def get_authorization_code():
    auth_url = f"{AUTH_URL}?client_id={CLIENT_ID}&redirect_uri={REDIRECT_URI}&response_type=code"
    print(f"Opening authorization URL: {auth_url}")
    webbrowser.open(auth_url)
    print("Please log in and authorize the application.")
    print("After authorization, you will be redirected to a page.")
    print("Copy the entire URL of the page you are redirected to and paste it here:")
    redirect_url = input("Enter the full redirect URL: ").strip()
    parsed_url = urlparse(redirect_url)
    code = parse_qs(parsed_url.query).get('code', [None])[0]
    print(f"Extracted code: {code}")
    return code

def get_access_token(code):
    data = {
        'grant_type': 'authorization_code',
        'client_id': CLIENT_ID,
        'client_secret': CLIENT_SECRET,
        'code': code,
        'redirect_uri': REDIRECT_URI
    }
    print(f"Requesting access token with data: {data}")
    response = requests.post(TOKEN_URL, data=data)
    print(f"Token response status code: {response.status_code}")
    print(f"Token response content: {response.text}")
    if response.status_code != 200:
        return None
    return response.json().get('access_token')

def handle_callback(code):
    access_token = get_access_token(code)
    if not access_token:
        return {'error': 'Failed to obtain token'}, 400
    
    headers = {'Authorization': f'Bearer {access_token}'}
    print(f"Making request to {BASE_URL}/api/complete/intra42/ with headers: {headers}")
    response = requests.get(f"{BASE_URL}/api/complete/intra42/", headers=headers)
    print(f"Callback response status code: {response.status_code}")
    print(f"Callback response content: {response.text}")
    
    if response.status_code == 409:
        return response.json(), 409
    elif response.status_code == 200:
        return response.json(), 200
    else:
        return {'error': 'Unexpected response from server'}, response.status_code

def resolve_conflicts(intra_id, proposed_data):
    while True:
        print("\nThere are conflicts with the user information.")
        print("Current proposed data:")
        for key, value in proposed_data.items():
            print(f"{key}: {value}")
        
        username = input("Enter a new username (or press Enter to keep current): ").strip()
        email = input("Enter a new email (or press Enter to keep current): ").strip()

        if username:
            proposed_data['username'] = username
        if email:
            proposed_data['email'] = email

        data = {**proposed_data, 'intra_id': intra_id}
        response = requests.post(f"{BASE_URL}/api/resolve-conflicts/", json=data)
        if response.status_code == 201:
            return response.json()
        else:
            print("Conflict still exists. Please try again.")
            print(response.json())

def main():
    start_time = time.time()
    auth_code = get_authorization_code()
    if not auth_code:
        print("Failed to obtain authorization code.")
        return
    
    elapsed_time = time.time() - start_time
    print(f"Time elapsed since starting: {elapsed_time} seconds")

    response_data, status_code = handle_callback(auth_code)

    if status_code == 200:
        print("Login successful!")
        print(f"User ID: {response_data['user_id']}")
        print(f"Username: {response_data['username']}")
        print(f"Email: {response_data['email']}")
    elif status_code == 201:
        print("New user created and logged in successfully!")
        print(f"User ID: {response_data['user_id']}")
        print(f"Username: {response_data['username']}")
        print(f"Email: {response_data['email']}")
    elif status_code == 409:
        print("Conflict detected. User information:")
        print(f"Intra ID: {response_data['intra_id']}")
        print("Proposed data:")
        for key, value in response_data['proposed_data'].items():
            print(f"  {key}: {value}")
        print("Errors:")
        for key, errors in response_data['errors'].items():
            for error in errors:
                print(f"  {key}: {error}")
        
        resolved_data = resolve_conflicts(response_data['intra_id'], response_data['proposed_data'])
        print("Conflict resolved and user created!")
        print(f"User ID: {resolved_data['user_id']}")
        print(f"Username: {resolved_data['username']}")
        print(f"Email: {resolved_data['email']}")
    else:
        print(f"Unexpected response: {status_code}")
        print(response_data)

if __name__ == "__main__":
    main()