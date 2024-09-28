from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework import permissions, status
from django.utils.translation import gettext as _
from rest_framework_simplejwt.tokens import RefreshToken
from rest_framework_simplejwt.exceptions import TokenError
from rest_framework.permissions import IsAuthenticated
from django.contrib.auth import get_user_model, login
from django.core.mail import send_mail
from django.conf import settings
from django.shortcuts import redirect
import random, string, requests

from .models import TwoFactorCode

from .serializers import UserSerializer, LoginSerializer, RegisterSerializer
from .serializers import PasswordChangeSerializer, ProfileUpdateSerializer
from .serializers import PasswordResetSerializer, IntraUserSerializer

User = get_user_model()

class UserView(APIView):
    permission_classes = (permissions.IsAuthenticated,)

    def get(self, request):
        serializer = UserSerializer(request.user)
        return Response(serializer.data)


class LoginView(APIView):
    permission_classes = (permissions.AllowAny,)

    def post(self, request):
        serializer = LoginSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        user = serializer.get_user(serializer.validated_data)
        
        if user is None:
            return Response({'detail': _('Invalid username or password.')}, status=status.HTTP_401_UNAUTHORIZED)

        if user.is_2fa_enabled:
            # Generate and send 2FA code
            two_factor_code = TwoFactorCode.generate_code(user)
            send_mail(
                'Your 2FA Code',
                f'Your 2FA code is: {two_factor_code.code}',
                settings.DEFAULT_FROM_EMAIL,
                [user.email],
                fail_silently=False,
            )

            return Response({
                'detail': 'Please check your email for the 2FA code.',
                'user_id': user.id,
                'requires_2fa': True
            }, status=status.HTTP_200_OK)
        else:
            refresh = RefreshToken.for_user(user)
            return Response({
                'refresh': str(refresh),
                'access': str(refresh.access_token),
                'user': UserSerializer(user).data,
                'requires_2fa': False
            }, status=status.HTTP_200_OK)


class RegisterView(APIView):
    permission_classes = (permissions.AllowAny,)

    def post(self, request):
        serializer = RegisterSerializer(data=request.data)
        if serializer.is_valid():
            user = serializer.save()
            refresh = RefreshToken.for_user(user)
            return Response({
                'refresh': str(refresh),
                'access': str(refresh.access_token),
                'user': UserSerializer(user).data
            }, status=status.HTTP_201_CREATED)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


class LogoutView(APIView):
    permission_classes = (IsAuthenticated,)

    def post(self, request):
        try:
            refresh_token = request.data.get("refresh_token")
            if refresh_token:
                token = RefreshToken(refresh_token)
                token.blacklist()
                return Response({"detail": "Successfully logged out."}, status=status.HTTP_200_OK)
            else:
                return Response({"detail": "Refresh token is required."}, status=status.HTTP_400_BAD_REQUEST)
        except TokenError:
            return Response({"detail": "Invalid token."}, status=status.HTTP_400_BAD_REQUEST)


class PasswordChangeView(APIView):
    permission_classes = (IsAuthenticated,)

    def post(self, request):
        serializer = PasswordChangeSerializer(data=request.data, context={'request': request})
        if serializer.is_valid():
            serializer.save()
            return Response({"detail": "Password successfully changed."}, status=status.HTTP_200_OK)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


class DeleteAccountView(APIView):
    permission_classes = (IsAuthenticated,)

    def delete(self, request):
        user = request.user
        user.delete()
        return Response({"detail": "User account has been deleted."}, status=status.HTTP_204_NO_CONTENT)


class ProfileUpdateView(APIView):
    permission_classes = (IsAuthenticated,)

    def put(self, request):
        serializer = ProfileUpdateSerializer(request.user, data=request.data, context={'request': request}, partial=True)
        if serializer.is_valid():
            serializer.save()
            return Response(serializer.data)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

def generate_temp_password(length=10):
    characters = string.ascii_letters + string.digits
    return ''.join(random.choice(characters) for i in range(length))


class PasswordResetView(APIView):
    def post(self, request):
        serializer = PasswordResetSerializer(data=request.data)
        if serializer.is_valid():
            email = serializer.validated_data['email']
            try:
                user = User.objects.get(email=email)
                temp_password = generate_temp_password()
                user.set_password(temp_password)
                user.save()
                
                # Send email with temporary password
                send_mail(
                    'Password Reset',
                    f'Your temporary password is: {temp_password}\nPlease log in and change your password immediately.',
                    settings.DEFAULT_FROM_EMAIL,
                    [email],
                    fail_silently=False,
                )
                
                return Response({"detail": "Temporary password has been sent to your email."}, status=status.HTTP_200_OK)
            except User.DoesNotExist:
                return Response({"detail": "User with this email does not exist."}, status=status.HTTP_400_BAD_REQUEST)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


class VerifyTwoFactorView(APIView):
    permission_classes = (permissions.AllowAny,)

    def post(self, request):
        user_id = request.data.get('user_id')
        code = request.data.get('code')

        try:
            user = User.objects.get(id=user_id)
            two_factor_code = TwoFactorCode.objects.filter(user=user).latest('created_at')

            if two_factor_code.is_valid() and two_factor_code.code == code:
                refresh = RefreshToken.for_user(user)
                return Response({
                    'refresh': str(refresh),
                    'access': str(refresh.access_token),
                    'user': UserSerializer(user).data
                }, status=status.HTTP_200_OK)
            else:
                return Response({'detail': 'Invalid or expired code.'}, status=status.HTTP_400_BAD_REQUEST)
        except User.DoesNotExist:
            return Response({'detail': 'User not found.'}, status=status.HTTP_404_NOT_FOUND)
        except TwoFactorCode.DoesNotExist:
            return Response({'detail': 'No 2FA code found.'}, status=status.HTTP_400_BAD_REQUEST)


class Enable2FAView(APIView):
    permission_classes = (permissions.IsAuthenticated,)

    def post(self, request):
        user = request.user
        if user.is_2fa_enabled:
            return Response({'detail': '2FA is already enabled.'}, status=status.HTTP_400_BAD_REQUEST)

        # Generate and send 2FA code
        two_factor_code = TwoFactorCode.generate_code(user)
        send_mail(
            'Enable 2FA',
            f'Your 2FA code to enable two-factor authentication is: {two_factor_code.code}',
            settings.DEFAULT_FROM_EMAIL,
            [user.email],
            fail_silently=False,
        )

        return Response({'detail': 'Please check your email for the 2FA code to enable two-factor authentication.'}, status=status.HTTP_200_OK)


class Verify2FAEnableView(APIView):
    permission_classes = (permissions.IsAuthenticated,)

    def post(self, request):
        user = request.user
        code = request.data.get('code')

        try:
            two_factor_code = TwoFactorCode.objects.filter(user=user).latest('created_at')

            if two_factor_code.is_valid() and two_factor_code.code == code:
                user.is_2fa_enabled = True
                user.save()
                return Response({'detail': '2FA has been enabled successfully.'}, status=status.HTTP_200_OK)
            else:
                return Response({'detail': 'Invalid or expired code.'}, status=status.HTTP_400_BAD_REQUEST)
        except TwoFactorCode.DoesNotExist:
            return Response({'detail': 'No 2FA code found.'}, status=status.HTTP_400_BAD_REQUEST)


class Disable2FAView(APIView):
    permission_classes = (permissions.IsAuthenticated,)

    def post(self, request):
        user = request.user
        if not user.is_2fa_enabled:
            return Response({'detail': '2FA is not enabled.'}, status=status.HTTP_400_BAD_REQUEST)

        user.is_2fa_enabled = False
        user.save()
        return Response({'detail': '2FA has been disabled successfully.'}, status=status.HTTP_200_OK)



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
            # User exists, log them in
            login(request, existing_user)
            refresh = RefreshToken.for_user(existing_user)
            return Response({
                'message': 'Login successful',
                'user_id': existing_user.id,
                'username': existing_user.username,
                'email': existing_user.email,
                'access_token': str(refresh.access_token),
                'refresh_token': str(refresh),
            }, status=status.HTTP_200_OK)
        
        # New user, check for conflicts
        serializer = IntraUserSerializer(data={
            'username': intra_user_data['login'],
            'email': intra_user_data['email'],
            'first_name': intra_user_data.get('first_name', ''),
            'last_name': intra_user_data.get('last_name', ''),
        })

        if not serializer.is_valid():
            # There are conflicts, return the data for the user to modify
            return Response({
                'message': 'User information conflicts detected',
                'intra_id': intra_user_data['id'],
                'proposed_data': serializer.initial_data,
                'errors': serializer.errors
            }, status=status.HTTP_409_CONFLICT)

        # No conflicts, create the user
        user = User.objects.create_user(
            intra_id=str(intra_user_data['id']),
            username=serializer.validated_data['username'],
            email=serializer.validated_data['email'],
            first_name=serializer.validated_data['first_name'],
            last_name=serializer.validated_data['last_name'],
            password=User.objects.make_random_password()
        )

        login(request, user)
        refresh = RefreshToken.for_user(user)

        return Response({
            'message': 'User created and logged in successfully',
            'user_id': user.id,
            'username': user.username,
            'email': user.email,
            'access_token': str(refresh.access_token),
            'refresh_token': str(refresh),
        }, status=status.HTTP_201_CREATED)