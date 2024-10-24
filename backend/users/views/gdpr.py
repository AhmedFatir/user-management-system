from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework import status
from rest_framework.permissions import IsAuthenticated
from django.urls import reverse
from django.contrib.auth import get_user_model

User = get_user_model()

class GDPRAnonymizeDataView(APIView):
	permission_classes = (IsAuthenticated,)

	def post(self, request):
		user = request.user
		user.username = f"Anonymous_{user.id}"
		user.email = f"anonymous_{user.id}@example.com"
		user.first_name = "Anonymous"
		user.last_name = "User"
		user.save()
		return Response({"detail": "Your data has been anonymized."}, status=status.HTTP_200_OK)

class GDPRDashboardView(APIView):
	permission_classes = (IsAuthenticated,)

	def get(self, request):
		user = request.user
		data = {
			"username": user.username,
			"email": user.email,
			"data_management_options": {
				"view_profile": reverse('me'),
				"edit_profile": reverse('profile-update'),
				"change_avatar": reverse('upload-avatar'),
				"delete_account": reverse('delete-account'),
				"anonymize_data": reverse('anonymize-data'),
			},
			"privacy_policy": "https://www.termsfeed.com/live/0d2a133f-ba63-439b-ac52-8affaf87bd5d",
		}
		return Response(data)

class GDPRDataPrivacyRightsView(APIView):
	permission_classes = (IsAuthenticated,)

	def get(self, request):
		rights = {
			"gdpr_dashboard": reverse('gdpr-dashboard'),
			"view_profile": reverse('me'),
			"edit_profile": reverse('profile-update'),
			"change_avatar": reverse('upload-avatar'),
			"delete_account": reverse('delete-account'),
			"anonymize_data": reverse('anonymize-data'),
			"privacy_policy": "https://www.termsfeed.com/live/0d2a133f-ba63-439b-ac52-8affaf87bd5d",
		}
		return Response(rights)