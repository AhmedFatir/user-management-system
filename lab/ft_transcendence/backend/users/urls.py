from django.urls import path
from rest_framework_simplejwt.views import TokenObtainPairView, TokenRefreshView
from .views import RegisterView, LoginView, LogoutView, UserView, PasswordChangeView, DeleteAccountView, ProfileUpdateView

urlpatterns = [
    path('token/', TokenObtainPairView.as_view(), name='token_obtain_pair'),
    path('token/refresh/', TokenRefreshView.as_view(), name='token_refresh'),
    path('login', LoginView.as_view(), name="login"),
    path('register', RegisterView.as_view(), name="register"),
    path('logout', LogoutView.as_view(), name="logout"),
    path('user', UserView.as_view(), name="user"),
    path('password-change', PasswordChangeView.as_view(), name="password_change"),
    path('delete-account', DeleteAccountView.as_view(), name="delete-account"),
    path('profile-update', ProfileUpdateView.as_view(), name="profile-update"),
]
