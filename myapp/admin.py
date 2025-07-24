from django.contrib import admin
from .models import Login,OTP
# Register your models here.
admin.site.register(Login)


@admin.register(OTP)
class OTPAdmin(admin.ModelAdmin):
    list_display = ('id', 'email', 'otp_code', 'created_at')  # Corrected 'otp_code'
    search_fields = ('email', 'otp_code')
    ordering = ('-created_at',)