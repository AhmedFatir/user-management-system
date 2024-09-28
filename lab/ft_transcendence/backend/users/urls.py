from django.urls import path
from rest_framework_simplejwt.views import TokenObtainPairView, TokenRefreshView
from .views import RegisterView, LoginView, LogoutView, UserView, PasswordResetView
from .views import PasswordChangeView, DeleteAccountView, ProfileUpdateView
from .views import VerifyTwoFactorView, Enable2FAView, Verify2FAEnableView, Disable2FAView
from .views import IntraLoginView, IntraCallbackView

urlpatterns = [
    path('token/', TokenObtainPairView.as_view(), name='token_obtain_pair'),
    path('token/refresh/', TokenRefreshView.as_view(), name='token_refresh'),
    path('login/', LoginView.as_view(), name="login"),
    path('register/', RegisterView.as_view(), name="register"),
    path('logout/', LogoutView.as_view(), name="logout"),
    path('user/', UserView.as_view(), name="user"),
    path('password-change/', PasswordChangeView.as_view(), name="password_change"),
    path('delete-account/', DeleteAccountView.as_view(), name="delete-account"),
    path('profile-update/', ProfileUpdateView.as_view(), name="profile-update"),
    path('password-reset/', PasswordResetView.as_view(), name='password_reset'),
    path('verify-2fa/', VerifyTwoFactorView.as_view(), name='verify_2fa'),
    path('enable-2fa/', Enable2FAView.as_view(), name='enable_2fa'),
    path('verify-enable-2fa/', Verify2FAEnableView.as_view(), name='verify_enable_2fa'),
    path('disable-2fa/', Disable2FAView.as_view(), name='disable_2fa'),
    
    path('login/intra42/', IntraLoginView.as_view(), name='intra_login'),
    path('complete/intra42/', IntraCallbackView.as_view(), name='intra_callback'),
]
