from django.db import models
from django.db.models import Model
from django.utils.timezone import now
# Create your models here.
class Login(models.Model):
    email = models.EmailField()
    password = models.TextField()

    def __str__(self):
        return self.email

class OTP(models.Model):
    email = models.EmailField()
    otp_code = models.CharField(max_length=6)
    created_at = models.DateTimeField(default=now)

    def is_valid(self):
        """Checks if the OTP is valid (not older than 5 minutes)."""
        return (now() - self.created_at).seconds > 300

    def __str__(self):
        return f"{self.email} - {self.otp_code}"
