# tests.py

from django.test import TestCase
from django.urls import reverse
from rest_framework.test import APIClient
from rest_framework import status
from django.contrib.auth import get_user_model
from rest_framework_simplejwt.tokens import RefreshToken

User = get_user_model()

class RegistrationTestCase(TestCase):
    def setUp(self):
        self.client = APIClient()
        self.register_url = reverse('register')
        self.user_data = {
            'username': 'testuser',
            'email': 'testuser@example.com',
            'password': 'testpass123',
            'password2': 'testpass123'
        }

    def test_registration(self):
        response = self.client.post(self.register_url, self.user_data)
        self.assertEqual(response.status_code, status.HTTP_201_CREATED)
        self.assertIn('refresh', response.data)
        self.assertIn('access', response.data)
        self.assertIn('user', response.data)
        self.assertEqual(User.objects.count(), 1)
        self.assertEqual(User.objects.get().username, 'testuser')

    def test_registration_with_invalid_data(self):
        invalid_data = self.user_data.copy()
        invalid_data['password2'] = 'wrongpassword'
        response = self.client.post(self.register_url, invalid_data)
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertEqual(User.objects.count(), 0)
    
    def test_registration_with_existing_email(self):
        User.objects.create_user(username='existinguser', email='testuser@example.com', password='testpass123')

        new_user_data = self.user_data.copy()
        new_user_data['username'] = 'newuser'
        response = self.client.post(self.register_url, new_user_data)
        
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertIn('email', response.data)
        self.assertIn('already exists', str(response.data['email']).lower())
        self.assertEqual(User.objects.count(), 1)  # Ensure no new user was created

    def test_registration_with_existing_username(self):
        User.objects.create_user(username='testuser', email='existinguser@example.com', password='testpass123')

        new_user_data = self.user_data.copy()
        new_user_data['email'] = 'newuser@example.com'
        response = self.client.post(self.register_url, new_user_data)
        
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertIn('username', response.data)
        self.assertIn('already exists', str(response.data['username']).lower())
        self.assertEqual(User.objects.count(), 1)  # Ensure no new user was created


class LoginTestCase(TestCase):

	def setUp(self):
		self.client = APIClient()
		self.login_url = reverse('login')

	def test_user_login(self):
		User.objects.create_user(username='testuser', email='testuser@example.com', password='testpass123')
		
		# Then, attempt to log in
		login_data = {
			'username': 'testuser',
			'password': 'testpass123'
		}
		response = self.client.post(self.login_url, login_data)
		self.assertEqual(response.status_code, status.HTTP_200_OK)
		self.assertIn('refresh', response.data)
		self.assertIn('access', response.data)
		self.assertIn('user', response.data)

	def test_user_login_with_invalid_credentials(self):
		login_data = {
			'username': 'nonexistentuser',
			'password': 'wrongpassword'
		}
		response = self.client.post(self.login_url, login_data)
		self.assertEqual(response.status_code, status.HTTP_401_UNAUTHORIZED)


class LogoutTestCase(TestCase):

	def setUp(self):
		self.client = APIClient()
		self.logout_url = reverse('logout')

	def test_logout(self):
		# First, create and log in a user
		user = User.objects.create_user(username='testuser', email='testuser@example.com', password='testpass123')
		refresh = RefreshToken.for_user(user)
		self.client.credentials(HTTP_AUTHORIZATION=f'Bearer {refresh.access_token}')

		# Then, attempt to log out
		response = self.client.post(self.logout_url, {'refresh_token': str(refresh)})
		self.assertEqual(response.status_code, status.HTTP_200_OK)

	def test_logout_without_refresh_token(self):
		# First, create and log in a user
		user = User.objects.create_user(username='testuser', email='testuser@example.com', password='testpass123')
		refresh = RefreshToken.for_user(user)
		self.client.credentials(HTTP_AUTHORIZATION=f'Bearer {refresh.access_token}')

		# Then, attempt to log out without providing a refresh token
		response = self.client.post(self.logout_url)
		self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)

	def test_logout_with_invalid_token(self):
		# First, create and log in a user
		user = User.objects.create_user(username='testuser', email='testuser@example.com', password='testpass123')
		refresh = RefreshToken.for_user(user)
		self.client.credentials(HTTP_AUTHORIZATION=f'Bearer {refresh.access_token}')

		# Then, attempt to log out with an invalid token
		response = self.client.post(self.logout_url, {'refresh_token': 'invalid_token'})
		self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)        
 
class PasswordChangeTestCase(TestCase):
	def setUp(self):
		self.client = APIClient()
		self.change_password_url = reverse('password_change')
		self.user = User.objects.create_user(
			username='testuser',
			email='testuser@example.com',
			password='oldpassword123'
		)
		self.refresh = RefreshToken.for_user(self.user)
		self.client.credentials(HTTP_AUTHORIZATION=f'Bearer {self.refresh.access_token}')

	def test_change_password_success(self):
		data = {
			'old_password': 'oldpassword123',
			'new_password': 'newpassword456'
		}
		response = self.client.post(self.change_password_url, data)
		self.assertEqual(response.status_code, status.HTTP_200_OK)
		self.user.refresh_from_db()
		self.assertTrue(self.user.check_password('newpassword456'))

	def test_change_password_incorrect_old_password(self):
		data = {
			'old_password': 'wrongoldpassword',
			'new_password': 'newpassword456'
		}
		response = self.client.post(self.change_password_url, data)
		self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
		self.user.refresh_from_db()
		self.assertFalse(self.user.check_password('newpassword456'))

	def test_change_password_invalid_new_password(self):
		data = {
			'old_password': 'oldpassword123',
			'new_password': '123'  # Too short, should fail validation
		}
		response = self.client.post(self.change_password_url, data)
		self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
		self.user.refresh_from_db()
		self.assertFalse(self.user.check_password('123'))

	def test_change_password_unauthenticated(self):
		self.client.credentials()  # Remove authentication
		data = {
			'old_password': 'oldpassword123',
			'new_password': 'newpassword456'
		}
		response = self.client.post(self.change_password_url, data)
		self.assertEqual(response.status_code, status.HTTP_401_UNAUTHORIZED)

	def test_change_password_missing_fields(self):
		data = {
			'old_password': 'oldpassword123'
		}
		response = self.client.post(self.change_password_url, data)
		self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)

		data = {
			'new_password': 'newpassword456'
		}
		response = self.client.post(self.change_password_url, data)
		self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
		
class DeleteAccountTestCase(TestCase):
	def setUp(self):
		self.client = APIClient()
		self.delete_account_url = reverse('delete-account')
		self.user = User.objects.create_user(
			username='testuser',
			email='testuser@example.com',
			password='testpassword123'
		)
		self.refresh = RefreshToken.for_user(self.user)

	def test_delete_account_unauthenticated(self):
		self.client.credentials()  # Remove authentication
		response = self.client.delete(self.delete_account_url)
		self.assertEqual(response.status_code, status.HTTP_401_UNAUTHORIZED)
		self.assertTrue(User.objects.filter(username='testuser').exists())

	def test_delete_account_invalid_token(self):
		self.client.credentials(HTTP_AUTHORIZATION='Bearer invalidtoken123')
		response = self.client.delete(self.delete_account_url)
		self.assertEqual(response.status_code, status.HTTP_401_UNAUTHORIZED)
		self.assertTrue(User.objects.filter(username='testuser').exists()) 

	def test_delete_account_success(self):
		self.client.credentials(HTTP_AUTHORIZATION=f'Bearer {self.refresh.access_token}')
		response = self.client.delete(self.delete_account_url)
		self.assertEqual(response.status_code, status.HTTP_204_NO_CONTENT)
		self.assertFalse(User.objects.filter(username='testuser').exists())


class ProfileUpdateTestCase(TestCase):
    def setUp(self):
        self.client = APIClient()
        self.profile_update_url = reverse('profile-update')
        self.user = User.objects.create_user(
            username='testuser',
            email='testuser@example.com',
            password='testpass123',
            first_name='Test',
            last_name='User'
        )
        self.refresh = RefreshToken.for_user(self.user)
        self.client.credentials(HTTP_AUTHORIZATION=f'Bearer {self.refresh.access_token}')

    def test_profile_update_success(self):
        data = {
            'first_name': 'Updated',
            'last_name': 'Name',
            'email': 'updated@example.com'
        }
        response = self.client.put(self.profile_update_url, data)
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.user.refresh_from_db()
        self.assertEqual(self.user.first_name, 'Updated')
        self.assertEqual(self.user.last_name, 'Name')
        self.assertEqual(self.user.email, 'updated@example.com')

    def test_profile_update_email_already_exists(self):
        User.objects.create_user(username='anotheruser', email='existing@example.com', password='pass123')
        data = {
            'email': 'existing@example.com'
        }
        response = self.client.put(self.profile_update_url, data)
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertIn('email', response.data)

    def test_profile_update_unauthenticated(self):
        self.client.credentials()  # Remove authentication
        data = {
            'first_name': 'Updated',
        }
        response = self.client.put(self.profile_update_url, data)
        self.assertEqual(response.status_code, status.HTTP_401_UNAUTHORIZED)


class UserTestCase(TestCase):
    
    def setUp(self):
        self.client = APIClient()
        self.users_url = reverse('users')
        self.user1 = User.objects.create_user(username='testuser1', email='testuser1@example.com', password='testpass123')
        self.user2 = User.objects.create_user(username='testuser2', email='testuser2@example.com', password='testpass123')

    def test_get_all_users_authenticated(self):
        refresh = RefreshToken.for_user(self.user1)
        self.client.credentials(HTTP_AUTHORIZATION=f'Bearer {refresh.access_token}')

        response = self.client.get(self.users_url)
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(len(response.data), 2)  # Assuming only the two users created in setUp

    def test_get_all_users_unauthenticated(self):
        response = self.client.get(self.users_url)
        self.assertEqual(response.status_code, status.HTTP_401_UNAUTHORIZED)

    def test_get_specific_user_authenticated(self):
        refresh = RefreshToken.for_user(self.user1)
        self.client.credentials(HTTP_AUTHORIZATION=f'Bearer {refresh.access_token}')

        response = self.client.get(reverse('user-detail', kwargs={'username': 'testuser2'}))
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(response.data['username'], 'testuser2')
        self.assertEqual(response.data['email'], 'testuser2@example.com')

    def test_get_specific_user_not_found(self):
        refresh = RefreshToken.for_user(self.user1)
        self.client.credentials(HTTP_AUTHORIZATION=f'Bearer {refresh.access_token}')

        response = self.client.get(reverse('user-detail', kwargs={'username': 'nonexistentuser'}))
        self.assertEqual(response.status_code, status.HTTP_404_NOT_FOUND)

    def test_get_specific_user_unauthenticated(self):
        response = self.client.get(reverse('user-detail', kwargs={'username': 'testuser1'}))
        self.assertEqual(response.status_code, status.HTTP_401_UNAUTHORIZED)

    def test_profile_invalid_token(self):
        self.client.credentials(HTTP_AUTHORIZATION='Bearer invalidtoken123')
        response = self.client.get(self.users_url)
        self.assertEqual(response.status_code, status.HTTP_401_UNAUTHORIZED)

    def test_profile_authenticated(self):
        refresh = RefreshToken.for_user(self.user1)
        self.client.credentials(HTTP_AUTHORIZATION=f'Bearer {refresh.access_token}')

        response = self.client.get(reverse('user-detail', kwargs={'username': 'testuser1'}))
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(response.data['username'], 'testuser1')
        self.assertEqual(response.data['email'], 'testuser1@example.com')