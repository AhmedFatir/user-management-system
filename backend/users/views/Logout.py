from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework import status
from rest_framework_simplejwt.tokens import RefreshToken
from rest_framework_simplejwt.exceptions import TokenError
from rest_framework.permissions import IsAuthenticated
import os

class LogoutView(APIView):
	permission_classes = (IsAuthenticated,)

	def post(self, request):
		try:
			refresh_token = request.data.get("refresh_token")
			if refresh_token:
				user = request.user
				user.is_online = False
				user.save()
				token = RefreshToken(refresh_token)
				token.blacklist()
				return Response({"detail": "Successfully logged out."}, status=status.HTTP_200_OK)
			else:
				return Response({"detail": "Refresh token is required."}, status=status.HTTP_400_BAD_REQUEST)
		except TokenError:
			return Response({"detail": "Invalid token."}, status=status.HTTP_400_BAD_REQUEST)



class DeleteAccountView(APIView):
	permission_classes = (IsAuthenticated,)

	def delete(self, request):
		user = request.user
		name = user.username

		user.friends.clear()
		user.incoming_requests.clear()
		user.outgoing_requests.clear()
		user.blocked_users.clear()

		if user.avatar and user.avatar.name != 'default.jpg':
			if os.path.isfile(user.avatar.path):
				os.remove(user.avatar.path)

		RefreshToken.for_user(user).blacklist()
		user.delete()
		return Response({"detail": f"{name}'s account and all associated data have been permanently deleted."}, status=status.HTTP_204_NO_CONTENT)
