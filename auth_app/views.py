import random
import logging
from django.utils.timezone import now
from django.core.mail import send_mail
from rest_framework import status, generics
from rest_framework.response import Response
from rest_framework.views import APIView
from rest_framework.permissions import IsAuthenticated
from rest_framework_simplejwt.tokens import RefreshToken
from django.contrib.auth import authenticate
from rest_framework_simplejwt.views import TokenObtainPairView

from .models import CustomUser
from .serializers import (
    RegisterSerializer, OTPVerifySerializer, LoginSerializer, 
    ForgotPasswordSerializer, ResetPasswordSerializer, UserProfileSerializer, MyTokenObtainPairSerializer
)

logger = logging.getLogger(__name__)

# User Registration View
class RegisterView(generics.CreateAPIView):
    serializer_class = RegisterSerializer

    def perform_create(self, serializer):
        user = serializer.save()
        user.is_verified = False  # Mark user as unverified until OTP verification
        user.generate_otp()
        
        # Send OTP email
        send_mail(
            'Your OTP Code',
            f'Your OTP code is {user.otp}',
            'noreply@example.com',
            [user.email],
            fail_silently=False,
        )
        return Response({"message": "User registered successfully. OTP sent to your email."}, status=status.HTTP_201_CREATED)

# OTP Verification View
class OTPVerifyView(APIView):
    def post(self, request):
        serializer = OTPVerifySerializer(data=request.data)
        if serializer.is_valid():
            email = serializer.validated_data['email']
            otp = serializer.validated_data['otp']

            user = CustomUser.objects.filter(email=email).first()
            if not user:
                return Response({"error": "User not found"}, status=status.HTTP_404_NOT_FOUND)

            if user.failed_attempts >= 3:
                return Response({"error": "Too many failed attempts. Try again later."}, status=status.HTTP_403_FORBIDDEN)

            # Check if OTP is valid
            if user.otp == otp and (now() - user.otp_created_at).seconds < 300:
                user.is_verified = True  # Mark user as verified
                user.otp = None
                user.failed_attempts = 0
                user.save()
                return Response({"message": "OTP verified successfully. You can now log in."}, status=status.HTTP_200_OK)

            user.failed_attempts += 1
            user.save()
            return Response({"error": "Invalid OTP"}, status=status.HTTP_400_BAD_REQUEST)

        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

# User Login View
class LoginView(APIView):
    def post(self, request):
        serializer = LoginSerializer(data=request.data)
        if serializer.is_valid():
            email = serializer.validated_data['email']
            password = serializer.validated_data['password']
            user = CustomUser.objects.filter(email=email).first()

            if user and user.check_password(password):
                if not user.is_verified:
                    return Response({"error": "Please verify your OTP before logging in."}, status=status.HTTP_403_FORBIDDEN)

                # Generate JWT tokens
                refresh = RefreshToken.for_user(user)
                access = refresh.access_token

                # Add user role to tokens
                refresh["role"] = user.role
                access["role"] = user.role

                return Response({
                    "access": str(access),
                    "refresh": str(refresh),
                    "id": user.id,
                    "role": user.role
                }, status=status.HTTP_200_OK)

            return Response({"error": "Invalid credentials"}, status=status.HTTP_400_BAD_REQUEST)

        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

# Forgot Password View
class ForgotPasswordView(APIView):
    def post(self, request):
        serializer = ForgotPasswordSerializer(data=request.data)
        if serializer.is_valid():
            email = serializer.validated_data['email']
            user = CustomUser.objects.filter(email=email).first()

            if not user:
                return Response({"error": "User not found"}, status=status.HTTP_404_NOT_FOUND)

            otp = str(random.randint(100000, 999999))
            user.otp = otp
            user.otp_created_at = now()
            user.save()

            # Send password reset OTP email
            send_mail(
                "Password Reset OTP",
                f"Your OTP for password reset is {otp}",
                "noreply@example.com",
                [user.email],
                fail_silently=False,
            )
            return Response({"message": "OTP sent to your email."}, status=status.HTTP_200_OK)

        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

# Reset Password View
class ResetPasswordView(APIView):
    def post(self, request):
        serializer = ResetPasswordSerializer(data=request.data)
        if serializer.is_valid():
            email = serializer.validated_data['email']
            otp = serializer.validated_data['otp']
            new_password = serializer.validated_data['new_password']

            user = CustomUser.objects.get(email=email)

            if not user or user.otp != otp or (now() - user.otp_created_at).seconds > 300:
                return Response({"error": "Invalid OTP or OTP expired"}, status=status.HTTP_400_BAD_REQUEST)

            user.set_password(new_password)
            user.otp = None
            user.failed_attempts = 0
            user.save()

            return Response({"message": "Password has been reset successfully."}, status=status.HTTP_200_OK)

        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

# User Profile View
class UserProfileView(APIView):
    permission_classes = [IsAuthenticated]

    def get(self, request):
        serializer = UserProfileSerializer(request.user)
        return Response(serializer.data, status=status.HTTP_200_OK)

# Logout View
class LogoutView(APIView):
    permission_classes = [IsAuthenticated]

    def post(self, request):
        try:
            refresh_token = request.data.get("refresh")
            token = RefreshToken(refresh_token)
            token.blacklist()
            return Response({"message": "User logged out successfully."}, status=status.HTTP_200_OK)
        except Exception:
            return Response({"error": "Invalid refresh token"}, status=status.HTTP_400_BAD_REQUEST)

# Custom JWT Token View
class MyTokenObtainPairView(TokenObtainPairView):
    serializer_class = MyTokenObtainPairSerializer

# Get User Details by Role
class GetUserDetailsView(APIView):
    def post(self, request):
        role = request.data.get("role")
        if not role:
            return Response({"error": "Role is required"}, status=status.HTTP_400_BAD_REQUEST)

        users = CustomUser.objects.filter(role=role).values("id", "name", "email")
        return Response({"users": list(users)}, status=status.HTTP_200_OK)
    


class UserCountsView(APIView):
    permission_classes = [IsAuthenticated]  # Requires authentication

    def get(self, request):
        total_users = CustomUser.objects.count()
        users = CustomUser.objects.filter(role="customer").count()
       
        vendors = CustomUser.objects.filter(role="vendor").count()

        return Response({
            "total_users": total_users,
            "customer": users,
           
            "vendors": vendors
        }, status=200)
    

class UpdateUserProfileView(APIView):
    permission_classes = [IsAuthenticated]

    def put(self, request):
        user = request.user
        data = request.data

        if "address" in data:
            user.address = data["address"]
        if "phone_number" in data:
            user.phone_number = data["phone_number"]

        user.save()
        serializer = UserProfileSerializer(user)
        return Response(serializer.data, status=status.HTTP_200_OK)


class GetAllUsersView(APIView):
    permission_classes = [IsAuthenticated]

    def get(self, request):
        if request.user.role != "admin":
            return Response({"error": "You are not authorized to access this resource."}, status=status.HTTP_403_FORBIDDEN)

        users = CustomUser.objects.all().values("id", "name", "email", "role", "address", "phone_number")
        return Response({"users": list(users)}, status=status.HTTP_200_OK)
