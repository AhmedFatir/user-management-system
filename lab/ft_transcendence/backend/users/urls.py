from django.urls import path
from rest_framework_simplejwt.views import TokenRefreshView

from .views.Register import RegisterView
from .views.Login import LoginView, MyTokenObtainPairView
from .views.Logout import LogoutView, DeleteAccountView
from .views.users import UsersView, UserDetailView
from .views.Profile import ProfileUpdateView, AvatarUploadView
from .views.Passwords import PasswordResetView, PasswordChangeView
from .views.TwoFactor import VerifyTwoFactorView, Enable2FAView, Verify2FAEnableView, Disable2FAView
from .views.Intra42 import IntraLoginView, IntraCallbackView

urlpatterns = [
    path('token/', MyTokenObtainPairView.as_view(), name='token_obtain_pair'),
    path('token/refresh/', TokenRefreshView.as_view(), name='token_refresh'),
    
    path('login/', LoginView.as_view(), name="login"),
    path('register/', RegisterView.as_view(), name="register"),
    path('users/', UsersView.as_view(), name="users"),
    path('users/<str:username>/', UserDetailView.as_view(), name="user-detail"),

    path('logout/', LogoutView.as_view(), name="logout"),
    path('delete-account/', DeleteAccountView.as_view(), name="delete-account"),
    
    path('password-change/', PasswordChangeView.as_view(), name="password_change"),
    path('password-reset/', PasswordResetView.as_view(), name='password_reset'),
    
    path('verify-2fa/', VerifyTwoFactorView.as_view(), name='verify_2fa'),
    path('enable-2fa/', Enable2FAView.as_view(), name='enable_2fa'),
    path('verify-enable-2fa/', Verify2FAEnableView.as_view(), name='verify_enable_2fa'),
    path('disable-2fa/', Disable2FAView.as_view(), name='disable_2fa'),
    
    path('login/intra42/', IntraLoginView.as_view(), name='intra_login'),
    path('complete/intra42/', IntraCallbackView.as_view(), name='intra_callback'),

    path('profile-update/', ProfileUpdateView.as_view(), name="profile-update"),
    path('upload-avatar/', AvatarUploadView.as_view(), name='upload-avatar'),

]
