from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework import permissions, status
from rest_framework_simplejwt.tokens import RefreshToken
from django.core.mail import send_mail
from django.conf import settings
from django.contrib.auth import get_user_model

from users.models import TwoFactorCode
from users.serializers import UserSerializer

User = get_user_model()

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

