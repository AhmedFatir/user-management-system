from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework import status
from rest_framework_simplejwt.tokens import RefreshToken
from django.contrib.auth import login, get_user_model
from django.conf import settings
from django.shortcuts import redirect
import requests
from django.db.models import Q

User = get_user_model()

from users.serializers import UserSerializer


class IntraLoginView(APIView):
	def get(self, request):
		url = f"{settings.INTRA_AUTHORIZATION_BASE_URL}?client_id={settings.INTRA_CLIENT_ID}&redirect_uri={settings.INTRA_REDIRECT_URI}&response_type=code"
		return redirect(url)


class IntraCallbackView(APIView):
	def get(self, request):
		code = request.GET.get('code')
		if not code:
			return Response({'error': 'No code provided'}, status=status.HTTP_400_BAD_REQUEST)

		# Exchange code for token
		token_response = requests.post(settings.INTRA_TOKEN_URL, data={
			'grant_type': 'authorization_code',
			'client_id': settings.INTRA_CLIENT_ID,
			'client_secret': settings.INTRA_CLIENT_SECRET,
			'code': code,
			'redirect_uri': settings.INTRA_REDIRECT_URI
		})

		if token_response.status_code != 200:
			return Response({'error': 'Failed to obtain token'}, status=status.HTTP_400_BAD_REQUEST)

		access_token = token_response.json()['access_token']

		# Get user data from Intra
		user_response = requests.get(settings.INTRA_USER_DATA_URL, headers={
			'Authorization': f'Bearer {access_token}'
		})

		if user_response.status_code != 200:
			return Response({'error': 'Failed to obtain user data'}, status=status.HTTP_400_BAD_REQUEST)

		intra_user_data = user_response.json()

		# Check if user exists
		existing_user = User.objects.filter(intra_id=str(intra_user_data['id'])).first()

		if existing_user:
			login(request, existing_user)
			existing_user.is_online = True
			existing_user.save()
			refresh = RefreshToken.for_user(existing_user)
			return Response({
				'message': 'Login successful',
				'refresh': str(refresh),
				'access': str(refresh.access_token),
				'user': UserSerializer(existing_user, context={'request': request}).data,
				'requires_2fa': False
			}, status=status.HTTP_200_OK)

		# New user, handle username and email conflicts
		base_username = intra_user_data['login']
		username = base_username
		email_username, email_domain = intra_user_data['email'].split('@')
		email = intra_user_data['email']
		suffix = 1
		while User.objects.filter(Q(username=username) | Q(email=email)).exists():
			username = f"{base_username}_{suffix}"
			email = f"{email_username}_{suffix}@{email_domain}"
			suffix += 1

		# Create the user
		user = User.objects.create_user(
			intra_id=str(intra_user_data['id']),
			username=username,
			email=email,
			first_name=intra_user_data.get('first_name', ''),
			last_name=intra_user_data.get('last_name', ''),
			password=User.objects.make_random_password()
		)

		# Set the avatar for the new user
		avatar_url = intra_user_data['image']['link']
		user.set_avatar_from_url(avatar_url)

		# Log the user in
		login(request, user)
		user.is_online = True
		user.save()
		refresh = RefreshToken.for_user(user)
		return Response({
			'message': 'User created and logged in successfully',
			'refresh': str(refresh),
			'access': str(refresh.access_token),
			'user': UserSerializer(user, context={'request': request}).data,
			'requires_2fa': False
		}, status=status.HTTP_201_CREATED)