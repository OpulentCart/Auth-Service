from django.urls import path
from .views import (
    RegisterView, OTPVerifyView, LoginView, ForgotPasswordView, 
    ResetPasswordView, UserProfileView, LogoutView, MyTokenObtainPairView, GetUserDetailsView,UserCountsView,UpdateUserProfileView
    ,GetAllUsersView
)
from rest_framework_simplejwt.views import TokenRefreshView

urlpatterns = [
    # User Registration & OTP Verification
    path('auth/register/', RegisterView.as_view(), name='register'),  # Register a new user
    path('auth/verify-otp/', OTPVerifyView.as_view(), name='verify_otp'),  # Verify OTP for user activation

    # Authentication & Token Management
    path('auth/login/', LoginView.as_view(), name='login'),  # Login with email and password
    path('auth/token/', MyTokenObtainPairView.as_view(), name='token_obtain_pair'),  # Obtain JWT access & refresh token
    path('auth/token/refresh/', TokenRefreshView.as_view(), name='token_refresh'),  # Refresh expired access token
    path('auth/logout/', LogoutView.as_view(), name='logout'),  # Logout and blacklist refresh token

    # Password Recovery
    path('auth/forgot-password/', ForgotPasswordView.as_view(), name='forgot_password'),  # Request OTP for password reset
    path('auth/reset-password/', ResetPasswordView.as_view(), name='reset_password'),  # Reset password using OTP

    # User Profile
    path('auth/user-profile/', UserProfileView.as_view(), name='user_profile'),  # Retrieve user profile data

    # Fetch User Details based on Role
    path('auth/getuser-details/', GetUserDetailsView.as_view(), name='getuser_details'),  # Get users by role
    
    path('auth/user-counts/', UserCountsView.as_view(), name='user_counts'),

    path('auth/update-profile/', UpdateUserProfileView.as_view(), name='update_profile'),

    path('auth/all-users/', GetAllUsersView.as_view(), name='all_users'),

]
