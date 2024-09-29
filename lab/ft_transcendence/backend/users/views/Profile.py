from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework import permissions, status
from rest_framework.permissions import IsAuthenticated
from django.contrib.auth import get_user_model


from users.serializers import UserAvatarSerializer, FriendRequestSerializer
from users.serializers import ProfileUpdateSerializer, UserSerializer

User = get_user_model()

class ProfileUpdateView(APIView):
    permission_classes = (IsAuthenticated,)

    def put(self, request):
        serializer = ProfileUpdateSerializer(request.user, data=request.data, context={'request': request}, partial=True)
        if serializer.is_valid():
            serializer.save()
            return Response(serializer.data)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


class FriendRequestView(APIView):
    permission_classes = (IsAuthenticated,)

    def post(self, request):
        serializer = FriendRequestSerializer(data=request.data)
        if serializer.is_valid():
            username = serializer.validated_data['username']
            try:
                friend = User.objects.get(username=username)
                request.user.friends.add(friend)
                return Response({"detail": f"Friend request sent to {username}"})
            except User.DoesNotExist:
                return Response({"detail": "User not found"}, status=status.HTTP_404_NOT_FOUND)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

class FriendListView(APIView):
    permission_classes = (IsAuthenticated,)

    def get(self, request):
        friends = request.user.friends.all()
        serializer = UserSerializer(friends, many=True)
        return Response(serializer.data)

class AvatarUploadView(APIView):
    permission_classes = (IsAuthenticated,)

    def post(self, request):
        if 'avatar' not in request.data:
            return Response({'avatar': ['This field is required.']}, status=status.HTTP_400_BAD_REQUEST)
        
        serializer = UserAvatarSerializer(request.user, data=request.data, partial=True)
        if serializer.is_valid():
            serializer.save()
            return Response(UserSerializer(request.user).data)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)