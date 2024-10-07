from django.shortcuts import render
from .models import User
from rest_framework import generics
from .serializers import UserRegistrationSerializer
from rest_framework.permissions import IsAuthenticated, AllowAny
from rest_framework.response import Response
from rest_framework import status
from rest_framework.views import APIView
from django.shortcuts import get_object_or_404
from .serializers import CurrentUserSerializer, CurrentUserSettingsSerializer
from rest_framework_simplejwt.views import TokenObtainPairView, TokenRefreshView
from rest_framework_simplejwt.tokens import RefreshToken, TokenError
import requests
from user_management.models import Player
import os
import random
from game.models import  Achievement,UserAchievement
from channels.layers import get_channel_layer
from asgiref.sync import async_to_sync
from user_management.models import Notification
import pyotp
import qrcode
from django.http import FileResponse, Http404
# Create your views here.
 
token_url = 'https://api.intra.42.fr/oauth/token'
user_info_url = 'https://api.intra.42.fr/v2/me'

class UserView(APIView):
    pass
    # def get(self ,request, user_id):
    #     user = get_object_or_404(User, pk=user_id)
    #     serializer = CurrentUserSerializer(user)
    #     return(Response(serializer.data))

class CurrentUserView(APIView):
    def patch(self, request):
        user = request.user
        serializer = CurrentUserSettingsSerializer(user, data=request.data, partial=True, context={'request': request})
        if serializer.is_valid():
            serializer.save()
            return Response({"message" : "the user has been updated"}, status=status.HTTP_200_OK)
        return(Response(serializer.errors,  status=status.HTTP_400_BAD_REQUEST))
        



class UserRegistration(APIView):
    permission_classes = [AllowAny]
    def post(self, request):
        serializer = UserRegistrationSerializer(data=request.data)
        if serializer.is_valid():
            avatar_type = request.data.get('avatar_type')
            avatar_file = request.FILES.get('avatar')
            if avatar_file:
                serializer.validated_data['avatar'] = avatar_file
            elif avatar_type:
                serializer.validated_data['avatar'] = f'avatars/{avatar_type}.png'
            else:
                return Response({"message": "No avatar provided"}, status=status.HTTP_400_BAD_REQUEST)
            user = serializer.save()
            self.unlock_first_register_achievement(user)
            return Response({"message": "User registered successfully"}, status=status.HTTP_201_CREATED)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
    
    def unlock_first_register_achievement(self, user):
        achievement, _ = Achievement.objects.get_or_create(
            title="Welcome Aboard",
            defaults={'description': "Create your first account."}
        )
   
        UserAchievement.objects.create(
            user=user,
            achievement=achievement,
            unlocked=True
        )
        Notification.objects.create(
            recipient=user,
            sender=user,
            message='You Got a new Achievment',
            title='Welcome Aboard',
            description='Create your first account.',
        )

        channel_layer = get_channel_layer()
        async_to_sync(channel_layer.group_send)(
            f'notifications_{user.id}',
            {
                'type': 'notification_message',
                'message': 'Got a new Achievment'
            }
        )

class CustomTokenObtainPairView(TokenObtainPairView):
    def post(self, request, *args, **kwargs):
        response = super().post(request, *args, **kwargs)
        if response.status_code == status.HTTP_200_OK:
            user = get_object_or_404(User, username=request.data['username'])
            response.data['username'] = request.data['username']
            if(user.is_2fa_enabled):
                response.data['2fa_required'] = True
                del response.data["refresh"]
                return response
            else:
                refreshToken = response.data['refresh']
                response.set_cookie(
                    key = 'refresh',
                    value = refreshToken,
                    httponly = True,
                    #more options to add when nedded 
                )
                del response.data["refresh"]
            return response
        else:
            return response

class CustomTokenRefreshView(TokenRefreshView):
    def post(self, request, *args, **kwargs):
        refresh_token = request.COOKIES.get('refresh')
        if not refresh_token:
            return Response({'error': 'Refresh token not found in cookies'}, status=status.HTTP_400_BAD_REQUEST)
        try:
            refresh = RefreshToken(refresh_token)
            user_id = refresh['user_id']
            user = User.objects.get(id=user_id)
            #to do : catch specific error like Tokenerror and User.NotExist
        except:
            return Response({'error': 'User not found.'}, status=status.HTTP_404_NOT_FOUND)
        serializer = self.get_serializer(data={'refresh': refresh_token})
        serializer.is_valid(raise_exception=True)
        response = Response(serializer.validated_data, status=status.HTTP_200_OK)
        response.set_cookie(
            key='refresh',
            value=refresh_token,
            httponly = True,
            #more options to add when nedded 
        )
        return response
    

class CallbackView(APIView):
    permission_classes = [AllowAny]
    def post(self, request, *args, **kwargs):
        code = request.data.get('code')
        print(f"code: {code}")
        if not code:
            print("you touched my tralala")
            return Response({"error": "No code provided"}, status=400)
        data = {
            'grant_type'  : 'authorization_code',
            'client_id'    : os.getenv('CLIENT_ID'),
            'client_secret': os.getenv('CLIENT_SECRET'),
            "code"         : code,
            "redirect_uri" : os.getenv('REDIRECT_URI')
        }
        print(f"code: {data}")
        response = requests.post(token_url, data=data)
        if response.status_code != 200:
            print(response.status_code)
            return Response({"error": "Failed to fetch token"}, status=response.status_code)
        access_token = response.json().get('access_token')
        headers = {'Authorization': f'Bearer {access_token}'}
        user_info_response = requests.get(user_info_url, headers=headers)

        if user_info_response.status_code != 200:
            return Response({"error": "Failed to fetch user data"}, status=user_info_response.status_code)
        user_info = user_info_response.json()
        api_42_id = user_info['id']
        username = user_info['login']
        email = user_info.get('email', '')
        avatar = user_info['image']['link']
        # avatarList = [0, 1, 2, 4]
        user, created = User.objects.get_or_create(api_42_id=api_42_id, defaults={'username': f"{username}{api_42_id}", 'avatar' : avatar,'email': email})
        if created:
            user.set_avatar_from_url(avatar)
            user.save()
        # khasni nzid wa7ed check ila ken l user already exist 
        refresh = RefreshToken.for_user(user)
        access_token = str(refresh.access_token)
        refresh_token = str(refresh)
        if user.is_2fa_enabled:
            response_data = {
                'access': access_token,
                'username': username,
                '2fa_required': True
            }
            response = Response(response_data, status=status.HTTP_200_OK)
            # response.set_cookie(
            #     key='refresh',
            #     value=refresh_token,
            #     httponly = True,
            #     #more options to add when nedded 
            # )
            return response
        response_data = {
            'access': access_token
        }
        response = Response(response_data, status=status.HTTP_200_OK)
        response.set_cookie(
            key='refresh',
            value=refresh_token,
            httponly = True,
            #more options to add when nedded 
        )
        return response

 
class Enable2FA(APIView):

    def get(self, request):
        request.user.generate_otp_secret()
        otp_uri = request.user.get_otp_uri()
        if not os.path.exists('private_media/2fa'):
            os.makedirs('private_media/2fa')
        file_name = f'{request.user.username}_2fa.png'
        file_path = f'private_media/2fa/{file_name}'
        qrcode.make(otp_uri).save(file_path)
        return Response({"otp_uri": file_path}, status=status.HTTP_200_OK)
    
    def post(self, request):
        user = request.user
        otp = request.data.get('otp')
        
        if not otp:
            return Response({"error": "OTP is required"}, status=status.HTTP_400_BAD_REQUEST)
        
        if pyotp.TOTP(user.otp_secret).verify(otp):
            user.is_2fa_verified = True
            user.is_2fa_enabled = True
            user.save()
            refresh = RefreshToken.for_user(user)
            access_token = str(refresh.access_token)
            refresh_token = str(refresh)
            username = user.username
            response_data = {
                'access': access_token,
                'username': username,
                "message": "2FA has been verified"
            }
            response = Response(response_data, status=status.HTTP_200_OK)
            response.set_cookie(
                key='refresh',
                value=refresh_token,
                httponly=True,  
                secure=True,    
                samesite='None' 
            )
            file_name = f'{user.username}_2fa.png'
            file_path = f'private_media/2fa/{file_name}'
            if os.path.exists(file_path):
                os.remove(file_path)
            return response
        return Response({"error": "Invalid OTP"}, status=status.HTTP_400_BAD_REQUEST)


class Disable2FA(APIView):
    def delete(self, request):
        file_name = f'{request.user.username}_2fa.png'
        file_path = f'private_media/2fa/{file_name}'
        if os.path.exists(file_path):
            os.remove(file_path)
        user = request.user
        user.otp_secret = None
        user.is_2fa_enabled = False
        user.is_2fa_verified = False
        user.save()
        return Response({"message": "2FA has been disabled"}, status=status.HTTP_200_OK)
    


class LogoutView(APIView):
    def post(self, request):
        try:
            refresh_token = request.COOKIES.get('refresh')
            if not refresh_token:
                return Response({"error": "Refresh token not found in cookies"}, status=status.HTTP_400_BAD_REQUEST)
            token = RefreshToken(refresh_token)
            token.blacklist()
            return Response({"message": "Successfully logged out"}, status=status.HTTP_205_RESET_CONTENT)
        except Exception as e:
            return Response({"error": str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)


class ProtectedQRCodeView(APIView):
    permission_classes = [IsAuthenticated]  # Ensure the user is authenticated

    def get(self, request, file_name):
        user = request.user
        expected_file_name = f'{user.username}_2fa.png'
        file_path = f'private_media/2fa/{expected_file_name}'
        print(f"file path: {file_path}")
        # Ensure the file exists and the file name matches the expected file name
        if not os.path.exists(file_path) or expected_file_name != file_name:
            raise Http404("File not found or you don't have permission to access this file.")
        
        # Serve the file as a response
        return FileResponse(open(file_path, 'rb'), content_type='image/png')
