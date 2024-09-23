from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework import permissions, status
from django.http import HttpRequest
from django.contrib.auth import login, authenticate
from rest_framework.authentication import SessionAuthentication
from django.utils.translation import gettext as _
from django.contrib.auth import logout
from django.views.decorators.csrf import csrf_protect
from django.utils.decorators import method_decorator
from rest_framework_simplejwt.tokens import RefreshToken


from rest_framework.permissions import IsAuthenticated
from .serializers import LoginSerializer, RegisterSerializer, UserSerializer

class LoginView(APIView):
    permission_classes = (permissions.AllowAny,)

    def post(self, request):
        serializer = LoginSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        user = serializer.get_user(serializer.validated_data)
        if user is None:
            return Response({'detail': _('Invalid username or password.')}, status=status.HTTP_401_UNAUTHORIZED)
        refresh = RefreshToken.for_user(user)
        return Response({
            'refresh': str(refresh),
            'access': str(refresh.access_token),
            'user': UserSerializer(user).data
        }, status=status.HTTP_200_OK)

# class LogoutView(APIView):
#     permission_classes = (permissions.IsAuthenticated,)
    
#     @method_decorator(csrf_protect)
#     def post(self, request):
#         if not request.user.is_authenticated:
#             return Response({"detail": "You're not logged in."}, status=status.HTTP_400_BAD_REQUEST)
        
#         logout(request)
#         return Response({"detail": "Successfully logged out."}, status=status.HTTP_200_OK)

class LogoutView(APIView):
    permission_classes = (IsAuthenticated,)

    def post(self, request):
        try:
            refresh_token = request.data.get("refresh_token")
            token = RefreshToken(refresh_token)
            token.blacklist()
            return Response({"detail": "Successfully logged out."}, status=status.HTTP_200_OK)
        except Exception as e:
            return Response({"detail": str(e)}, status=status.HTTP_400_BAD_REQUEST)


class UserView(APIView):
    permission_classes = (permissions.IsAuthenticated,)

    def get(self, request):
        serializer = UserSerializer(request.user)
        return Response(serializer.data)

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