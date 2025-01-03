from django.urls import path
from rest_framework_simplejwt.views import TokenRefreshView

from .views.Register import RegisterView
from .views.Login import LoginView, MyTokenObtainPairView
from .views.Logout import LogoutView, DeleteAccountView
from .views.users import UsersView, UserDetailView, MeView
from .views.Profile import ProfileUpdateView, AvatarUploadView
from .views.Passwords import PasswordResetView, PasswordChangeView
from .views.TwoFactor import VerifyTwoFactorView, Enable2FAView, Verify2FAEnableView, Disable2FAView
from .views.Intra42 import IntraLoginView, IntraCallbackView
from .views.Friends import FriendRequestView, FriendRequestResponseView, FriendListView
from .views.Friends import FriendRequestListView, CancelFriendRequestView
from .views.Friends import BlockUserView, UnblockUserView, BlockedUsersListView
from .views.gdpr import GDPRAnonymizeDataView, GDPRDashboardView, GDPRDataPrivacyRightsView

urlpatterns = [
	path('token/', MyTokenObtainPairView.as_view(), name='token_obtain_pair'),
	path('token/refresh/', TokenRefreshView.as_view(), name='token_refresh'),
	
	path('login/', LoginView.as_view(), name="login"),
	path('register/', RegisterView.as_view(), name="register"),
	path('users/', UsersView.as_view(), name="users"),
	path('users/me/', MeView.as_view(), name="me"),
	path('users/<str:username>/', UserDetailView.as_view(), name="user-detail"),

	path('logout/', LogoutView.as_view(), name="logout"),
	path('delete-account/', DeleteAccountView.as_view(), name="delete-account"),
	
	path('password-change/', PasswordChangeView.as_view(), name="password_change"),
	path('password-reset/', PasswordResetView.as_view(), name='password_reset'),
	
	path('enable-2fa/', Enable2FAView.as_view(), name='enable_2fa'),
	path('verify-enable-2fa/', Verify2FAEnableView.as_view(), name='verify_enable_2fa'),
	path('verify-2fa/', VerifyTwoFactorView.as_view(), name='verify_2fa'),
	path('disable-2fa/', Disable2FAView.as_view(), name='disable_2fa'),
	
	path('login/intra42/', IntraLoginView.as_view(), name='intra_login'),
	path('complete/intra42/', IntraCallbackView.as_view(), name='intra_callback'),

	path('profile-update/', ProfileUpdateView.as_view(), name="profile-update"),
	path('upload-avatar/', AvatarUploadView.as_view(), name='upload-avatar'),

	path('friends/', FriendListView.as_view(), name='friend-list'),
	path('friend-request/<str:username>/', FriendRequestView.as_view(), name='friend-request'),
	path('friend-response/<str:username>/', FriendRequestResponseView.as_view(), name='friend-response'),
	path('cancel-friend-request/<str:username>/', CancelFriendRequestView.as_view(), name='cancel-friend-request'),
	path('friend-requests/', FriendRequestListView.as_view(), name='friend-requests'),

	path('block-user/<str:username>/', BlockUserView.as_view(), name='block-user'),
	path('unblock-user/<str:username>/', UnblockUserView.as_view(), name='unblock-user'),
	path('blocked-users/', BlockedUsersListView.as_view(), name='blocked-users-list'),
	
	path('anonymize-data/', GDPRAnonymizeDataView.as_view(), name='anonymize-data'),
	path('gdpr-dashboard/', GDPRDashboardView.as_view(), name='gdpr-dashboard'),
	path('data-privacy-rights/', GDPRDataPrivacyRightsView.as_view(), name='data-privacy-rights'),
]
