from rest_framework import serializers
from .models import OTP

class OTPSerializer(serializers.ModelSerializer):
    class Meta:
        model = OTP
        fields = ['id', 'email', 'otp_code', 'created_at']


from django.conf import settings
from django.contrib.auth import get_user_model
from google.auth.transport import requests as google_requests
from google.oauth2 import id_token as google_id_token
from rest_framework import serializers

# User = get_user_model()
#
#
# class GoogleAuthSerializer(serializers.Serializer):
#     id_token = serializers.CharField(write_only=True)
#
#     def validate_id_token(self, raw_token):
#         try:
#
#             id_info = google_id_token.verify_oauth2_token(
#                 raw_token,
#                 google_requests.Request(),
#                 settings.GOOGLE_OAUTH2_CLIENT_ID,
#             )
#         except ValueError:
#             raise serializers.ValidationError("Invalid or expired Google token")
#
#         # 2) Accept only verified primary e-mails
#         if not id_info.get("email_verified"):
#             raise serializers.ValidationError("Google e-mail not verified")
#
#         self._id_info = id_info        # stash for use in `create`
#         return raw_token
#
#     def create(self, validated_data):
#
#         info = self._id_info
#         email = info["email"].lower()
#
#         user, _ = User.objects.get_or_create(
#             username=email,      # keep unique
#             defaults={
#                 "email": email,
#                 "first_name": info.get("given_name", ""),
#                 "last_name": info.get("family_name", ""),
#             },
#         )
#         # Set an unusable password the first time
#         if not user.has_usable_password():
#             user.set_unusable_password()
#             user.save(update_fields=[])
#         return user



from google.auth.transport import requests as google_requests
from google.oauth2 import id_token as google_id_token
from django.conf import settings

# class GoogleAuthSerializer(serializers.Serializer):
#     id_token = serializers.CharField()
#
#     def validate_id_token(self, raw_token):
#         try:
#             # Verifies the ID token with Google's public keys
#             id_info = google_id_token.verify_oauth2_token(
#                 raw_token,
#                 google_requests.Request(),
#                 settings.GOOGLE_OAUTH2_CLIENT_ID
#             )
#         except ValueError:
#             raise serializers.ValidationError("Invalid or expired Google token")
#
#         # Check if the email is verified
#         if not id_info.get("email_verified"):
#             raise serializers.ValidationError("Google email not verified")
#
#         # Save ID info for later use
#         self._id_info = id_info
#         return raw_token


User = get_user_model()

class GoogleAuthSerializer(serializers.Serializer):
    id_token = serializers.CharField()

    def validate_id_token(self, raw_token):
        try:
            # Verifies the ID token with Google's public keys
            id_info = google_id_token.verify_oauth2_token(
                raw_token,
                google_requests.Request(),
                settings.GOOGLE_OAUTH2_CLIENT_ID
            )
        except ValueError:
            raise serializers.ValidationError("Invalid or expired Google token")

        # Check if the email is verified
        if not id_info.get("email_verified"):
            raise serializers.ValidationError("Google email not verified")

        # Save ID info for later use
        self._id_info = id_info
        return raw_token

    def create(self, validated_data):
        info = self._id_info
        email = info["email"].lower()

        user, _ = User.objects.get_or_create(
            username=email,  # keep unique
            defaults={
                "email": email,
                "first_name": info.get("given_name", ""),
                "last_name": info.get("family_name", ""),
            },
        )
        # Set an unusable password the first time
        if not user.has_usable_password():
            user.set_unusable_password()
            user.save()
        return user


from rest_framework import serializers

class SignupSerializer(serializers.Serializer):
    email = serializers.EmailField()
    password = serializers.CharField(write_only=True)

class LoginSerializer(serializers.Serializer):
    email = serializers.EmailField()
    password = serializers.CharField(write_only=True)