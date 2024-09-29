from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework import status
from rest_framework_simplejwt.tokens import RefreshToken
from rest_framework_simplejwt.exceptions import TokenError
from rest_framework.permissions import IsAuthenticated

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
		user.delete()
		return Response({"detail": "User account has been deleted."}, status=status.HTTP_204_NO_CONTENT)
