from django.urls import path,include
from rest_framework_simplejwt.views import TokenObtainPairView , TokenRefreshView
from .views import *

urlpatterns = [
    path("token/", CustomTokenObtainPairView.as_view(), name="get_token"),
    path("token/refresh", CustomTokenRefreshView.as_view(), name="refresh_token"),
    path("logout/", LogoutView.as_view(), name="logout"),
    path("user-auth/", include("rest_framework.urls")),
    path("user/register/", UserRegistration.as_view(), name="register"),
    path("user/me/", CurrentUserView.as_view(), name="get_user_info"),
    path("user/me/<int:user_id>", UserView.as_view(), name="get_user_info"),
    path("callback/", CallbackView.as_view(), name="auth_callback"),
    path("enable2fa/", Enable2FA.as_view(), name="enable_2fa"),
    path("disable2fa/", Disable2FA.as_view(), name="disable_2fa"),
    path('private_media/2fa/<str:file_name>', ProtectedQRCodeView.as_view(), name='protected_qrcode'),
] 