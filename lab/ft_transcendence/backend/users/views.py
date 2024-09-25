from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework import permissions, status
from django.utils.translation import gettext as _
from rest_framework_simplejwt.tokens import RefreshToken
from rest_framework_simplejwt.exceptions import TokenError
from rest_framework.permissions import IsAuthenticated
from django.contrib.auth import get_user_model
from django.core.mail import send_mail
from django.conf import settings
import random, string

from .models import TwoFactorCode, CustomUser


from .serializers import UserSerializer, LoginSerializer, RegisterSerializer
from .serializers import PasswordChangeSerializer, ProfileUpdateSerializer
from .serializers import PasswordResetSerializer

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