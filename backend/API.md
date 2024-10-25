# user-managment-system
## Description
- [Authentication](#1-Authentication)
- [Users Management](#2-Users-Management)
- [Password Management](#3-Password-Management)
- [2FA Management](#4-2FA-Management)
- [Intra42 Login](#5-Intra42-Login)
- [Profile Management](#6-Profile-Management)
- [Friends Management](#7-Friends-Management)
- [GDPR Compliance](#8-GDPR-Compliance)
## 1-Authentication
### Register
- **Endpoint**: `/api/register/`
  - **Method**: `POST`
  - **Description**: Registers a new user.
- **Request Body**:
```
{
  "username": "testuser",
  "email": "example@example.com",
  "password": "securepassword123",
  "password2": "securepassword123"
}
```
- **Response**:
  - `HTTP_201_CREATED`: If the user is created.
  - `HTTP_400_BAD_REQUEST`: If the user is not created.
---
### Login
- **Endpoint**: `/api/login/`
  - **Method**: `POST`
  - **Description**: Logs in a user and returns an access token and a refresh token.
- **Request Body**:
```
{
  "username": "testuser",
  "password": "securepassword123"
}
```
- **Response**:
  - `HTTP_200_OK`: If the user is logged in.
  - `HTTP_401_UNAUTHORIZED`: If the user is not logged in.
---
### Logout
- **Endpoint**: `/api/logout/`
  - **Method**: `POST`
  - **Description**: Logs out the current logged user.
  - **headers**: ```{"Authorization": f"Bearer {access_token}"}```
- **Request Body**:
```
{
  "refresh_token": "{{refresh_token}}"
}
```
  - **Response**:
    - `HTTP_200_OK`: If the user is logged out.
    - `HTTP_400_BAD_REQUEST`: If the refresh token is invalid.
    - `HTTP_401_UNAUTHORIZED`: If the user is not logged in.
---
### Delete Account
- **Endpoint**: `/api/delete-account/`
  - **Method**: `DELETE`
  - **Description**: Deletes the account of the current logged user.
  - **headers**: ```{"Authorization": f"Bearer {access_token}"}```
  - **Response**:
    - `HTTP_204_NO_CONTENT`: If the account is deleted.
    - `HTTP_401_UNAUTHORIZED`: If the user is not logged in.
---
### Refresh Token
- **Endpoint**: `/api//token/refresh/`
  - **Method**: `POST`
  - **Description**: Refreshes the access token.
- **Request Body**:
```
{
  "refresh_token": "{{refresh_token}}"
}
```
  - **Response**:
    - `HTTP_200_OK`: If the access token is refreshed.
    - `HTTP_400_BAD_REQUEST`: If the refresh token is invalid.
---
## 2-Users-Management
### Users List
- **Endpoint**: `/api/users/`
  - **Method**: `GET`
  - **Description**: Returns a list of all users
  - **headers**: ```{"Authorization": f"Bearer {access_token}"}```
  - **Response**:
    - `HTTP_200_OK`: If the users list is returned.
    - `HTTP_401_UNAUTHORIZED`: If the user is not logged in.
---
### User Info
- **Endpoint**: `/api/users/username/`
  - **Method**: `GET`
  - **Description**: Returns info about a specific user
  - **headers**: ```{"Authorization": f"Bearer {access_token}"}```
  - **Response**:
    - `HTTP_200_OK`: If the user is found.
    - `HTTP_404_NOT_FOUND`: If the user is not found.
    - `HTTP_401_UNAUTHORIZED`: If the user is not logged in.
---
### Current User Info
- **Endpoint**: `/api/users/me/`
  - **Method**: `GET`
  - **Description**: Returns info about the current logged user
  - **headers**: ```{"Authorization": f"Bearer {access_token}"}```
  - **Response**:
    - `HTTP_200_OK`: If the user is found.
    - `HTTP_401_UNAUTHORIZED`: If the user is not logged in.
---
## 3-Password-Management
### Change Password
- **Endpoint**: `/api/password-change/`
  - **Method**: `POST`
  - **Description**: Changes the password of the current logged user.
  - **headers**: ```{"Authorization": f"Bearer {access_token}"}```
- **Request Body**:
```
{
  "old_password": "securepassword123",
  "new_password": "newpassword456"
}
```
  - **Response**:
    - `HTTP_200_OK`: If the password is changed.
    - `HTTP_400_BAD_REQUEST`: If the old password is incorrect.
    - `HTTP_401_UNAUTHORIZED`: If the user is not logged in.
---
### Reset Password
- **Endpoint**: `/api/password-reset/`
  - **Method**: `POST`
  - **Description**: Sends an email to the user with a link to reset the password.
- **Request Body**:
```
{
  "email": "{{email}}"
}
```
  - **Response**:
    - `HTTP_200_OK`: If the reset link is sent.
    - `HTTP_400_BAD_REQUEST`: If the user's email is not found.
---
## 4-2FA-Management
### Enable 2FA
- **Endpoint**: `/api/enable-2fa/`
  - **Method**: `POST`
  - **Description**: Sends an email to the user with a link to enable 2FA.
  - **headers**: ```{"Authorization": f"Bearer {access_token}"}```
  - **Response**:
    - `HTTP_200_OK`: If the 2FA code is sent.
    - `HTTP_400_BAD_REQUEST`: If 2FA is already enabled.
    - `HTTP_401_UNAUTHORIZED`: If the user is not logged in.
---
### Verify Enable 2FA
- **Endpoint**: `/api/verify-enable-2fa/`
  - **Method**: `POST`
  - **Description**: Verifies the 2FA code and enables 2FA for the current logged user.
  - **headers**: ```{"Authorization": f"Bearer {access_token}"}```
- **Request Body**:
```
{
  "code": "{{enable_code}}"
}
```
  - **Response**:
    - `HTTP_200_OK`: If the code is correct.
    - `HTTP_400_BAD_REQUEST`: If the code is incorrect or expired.
    - `HTTP_401_UNAUTHORIZED`: If the user is not logged in.
---
### Verify 2FA In Login
- **Endpoint**: `/api/verify-2fa/`
  - **Method**: `POST`
  - **Description**: Verifies the 2FA code for the current logged user if 2FA is enabled.
- **Request Body**:
```
{
  "user_id": {{user_id}},
  "code": "{{2fa_code}}"
}
```
  - **Response**:
    - `HTTP_200_OK`: If the code is correct. 
    - `HTTP_400_BAD_REQUEST`: If the code is incorrect or expired or not found.
    - `HTTP_404_NOT_FOUND`: If the user is not found.
---
### Disable 2FA
- **Endpoint**: `/api/disable-2fa/`
  - **Method**: `POST`
  - **Description**: Disables 2FA for the current logged user.
  - **headers**: ```{"Authorization": f"Bearer {access_token}"}```
  - **Response**:
    - `HTTP_200_OK`: If the 2FA is disabled.
    - `HTTP_400_BAD_REQUEST`: If 2FA is not enabled.
    - `HTTP_401_UNAUTHORIZED`: If the user is not logged in.
---
## 5-Intra42-Login
### Intra42 Redirect
- **Endpoint**: `/api/login/intra42/`
  - **Method**: `GET`
  - **Description**: Redirects to the intra42 login page.
---
### Intra42 Complete
- **Endpoint**: `/api/complete/intra42/`
  - **Method**: `GET`
  - **Description**: Completes the intra42 login and Registers a new user or logs in an existing user, and fills the user's info with the intra42 info.
  - **Response**:
    - `HTTP_200_OK`: If the user is logged in. 
    - `HTTP_201_CREATED`: If the user is created.
    - `HTTP_400_BAD_REQUEST`: If no code provided, or Failed to obtain token, or Failed to obtain user info.
---
## 6-Profile-Management
### Profile Update
- **Endpoint**: `/api/profile-update/`
  - **Method**: `PUT`
  - **Description**: Updates the profile of the current logged user.
  - **headers**: ```{"Authorization": f"Bearer {access_token}"}```
- **Request Body**:
```
{
  "username": "updateduser",
  "first_name": "Updated",
  "last_name": "Name",
  "email": "updated@example.com"
}
```
  - **Response**:
    - `HTTP_200_OK`: If the profile is updated. 
    - `HTTP_400_BAD_REQUEST`: If the updated username or email is already taken.
    - `HTTP_401_UNAUTHORIZED`: If the user is not logged in.
---
### Upload Avatar
- **Endpoint**: `/api/upload-avatar/`
  - **Method**: `POST`
  - **Description**: Uploads an avatar for the current logged user (path or url).
  - **headers**: ```{"Authorization": f"Bearer {access_token}"}```
- **Request Body**:
```
{
  "avatar": "{{avatar}}"
}
```
  - **Response**:
    - `HTTP_200_OK`: If the avatar is uploaded.
    - `HTTP_400_BAD_REQUEST`: If the avatar is not uploaded.
    - `HTTP_401_UNAUTHORIZED`: If the user is not logged in.
---
## 7-Friends-Management
### Friends List
- **Endpoint**: `/api/friends/`
  - **Method**: `GET`
  - **Description**: Returns a list of all friends of the current logged user.
  - **headers**: ```{"Authorization": f"Bearer {access_token}"}```
  - **Response**:
    - `HTTP_200_OK`: If the friends list is returned.
    - `HTTP_401_UNAUTHORIZED`: If the user is not logged in.
---
### Add Friend
- **Endpoint**: `/api/friend-request/<str:username>/`
  - **Method**: `POST`
  - **Description**: Sends a friend request to a user.
  - **headers**: ```{"Authorization": f"Bearer {access_token}"}```
  - **Response**:
    - `HTTP_201_CREATED`: If the friend request is sent.
    - `HTTP_400_BAD_REQUEST`: If the friend request is not sent.
    - `HTTP_404_NOT_FOUND`: If the user is not found.
    - `HTTP_401_UNAUTHORIZED`: If the user is not logged in.
---
### Respond To Friend Request
- **Endpoint**: `/api/friend-response/<str:username>/`
  - **Method**: `POST`
  - **Description**: Responds to a friend request. either `accepts` or `rejects`.
  - **headers**: ```{"Authorization": f"Bearer {access_token}"}```
- **Request Body**:
```
{
  "action": "{{action}}"
}
```
  - **Response**:
    - `HTTP_200_OK`: If the friend request is responded.
    - `HTTP_400_BAD_REQUEST`: If the action is invalid.
    - `HTTP_404_NOT_FOUND`: If the user is not found.
    - `HTTP_401_UNAUTHORIZED`: If the user is not logged in.
---
### Cancel Friend Request
- **Endpoint**: `/api/cancel-friend-request/<str:username>/`
  - **Method**: `POST`
  - **Description**: Cancels a friend request.
  - **headers**: ```{"Authorization": f"Bearer {access_token}"}```
  - **Response**:
    - `HTTP_200_OK`: If the friend request is canceled.
    - `HTTP_400_BAD_REQUEST`: If the friend request is not canceled.
    - `HTTP_404_NOT_FOUND`: If the user is not found.
    - `HTTP_401_UNAUTHORIZED`: If the user is not logged in.
---
### List Incoming And Outgoing Friend Requests
- **Endpoint**: `/api/friend-requests/`
  - **Method**: `GET`
  - **Description**: Returns a list of incoming and outgoing friend requests.
  - **headers**: ```{"Authorization": f"Bearer {access_token}"}```
  - **Response**:
    - `HTTP_200_OK`: If the friend requests list is returned.
    - `HTTP_401_UNAUTHORIZED`: If the user is not logged in.
---
### Block User
- **Endpoint**: `/api/block-user/<str:username>/`
  - **Method**: `POST`
  - **Description**: Blocks a user.
  - **headers**: ```{"Authorization": f"Bearer {access_token}"}```
  - **Response**:
    - `HTTP_200_OK`: If the user is blocked.
    - `HTTP_404_NOT_FOUND`: If the user is not found.
    - `HTTP_400_BAD_REQUEST`: If the user is already blocked.
    - `HTTP_401_UNAUTHORIZED`: If the user is not logged in.
### Unblock User
- **Endpoint**: `/api/unblock-user/<str:username>/`
  - **Method**: `POST`
  - **Description**: Unblocks a user.
  - **headers**: ```{"Authorization": f"Bearer {access_token}"}```
  - **Response**:
    - `HTTP_200_OK`: If the user is unblocked.
    - `HTTP_404_NOT_FOUND`: If the user is not found.
    - `HTTP_400_BAD_REQUEST`: If the user is not blocked.
    - `HTTP_401_UNAUTHORIZED`: If the user is not logged in.
### List Blocked Users
- **Endpoint**: `/api/blocked-users/`
  - **Method**: `GET`
  - **Description**: Unblocks a user.
  - **headers**: ```{"Authorization": f"Bearer {access_token}"}```
  - **Response**:
    - `HTTP_200_OK`: If the user is unblocked.
    - `HTTP_404_NOT_FOUND`: If the user is not found.
    - `HTTP_400_BAD_REQUEST`: If the user is not blocked.
    - `HTTP_401_UNAUTHORIZED`: If the user is not logged in.
---
## 8-GDPR-Compliance
### GDPR Dashboard
- **Endpoint**: `/api/gdpr-dashboard/`
  - **Method**: `GET`
  - **Description**: Returns the GDPR dashboard of the current logged user.
  - **headers**: ```{"Authorization": f"Bearer {access_token}"}```
  - **Response**:
    - `HTTP_200_OK`: If the GDPR dashboard is returned.
    - `HTTP_401_UNAUTHORIZED`: If the user is not logged in.
---
### Anonymize Data
- **Endpoint**: `/api/anonymize-data/`
  - **Method**: `POST`
  - **Description**: Anonymizes the data of the current logged user.
  - **headers**: ```{"Authorization": f"Bearer {access_token}"}```
  - **Response**:
    - `HTTP_200_OK`: If the data is anonymized.
    - `HTTP_401_UNAUTHORIZED`: If the user is not logged in.
---
### Data Privacy Rights
- **Endpoint**: `/api/data-privacy-rights/`
  - **Method**: `GET`
  - **Description**: Returns the data privacy rights of the current logged user.
  - **headers**: ```{"Authorization": f"Bearer {access_token}"}```
  - **Response**:
    - `HTTP_200_OK`: If the data privacy rights are returned.
    - `HTTP_401_UNAUTHORIZED`: If the user is not logged in.

