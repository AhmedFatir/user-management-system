from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework import permissions, status
from django.utils.translation import gettext as _
from rest_framework_simplejwt.tokens import RefreshToken
from django.core.mail import send_mail
from django.conf import settings

from users.serializers import UserSerializer, LoginSerializer
from users.models import TwoFactorCode

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