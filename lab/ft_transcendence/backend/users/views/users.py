from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework import permissions, status
from rest_framework.permissions import IsAuthenticated
from django.contrib.auth import get_user_model


from users.serializers import UserSerializer

User = get_user_model()
    
class UsersView(APIView):
    permission_classes = (permissions.IsAuthenticated,)

    def get(self, request):
        users = User.objects.all()
        serializer = UserSerializer(users, many=True, context={'request': request})
        return Response(serializer.data)

class UserDetailView(APIView):
    permission_classes = (permissions.IsAuthenticated,)

    def get(self, request, username):
        try:
            user = User.objects.get(username=username)
            serializer = UserSerializer(user, context={'request': request})
            return Response(serializer.data)
        except User.DoesNotExist:
            return Response({"detail": "User not found."}, status=status.HTTP_404_NOT_FOUND)

class MeView(APIView):
    permission_classes = (permissions.IsAuthenticated,)

    def get(self, request):
        serializer = UserSerializer(request.user, context={'request': request})
        return Response(serializer.data)