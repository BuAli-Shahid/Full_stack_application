"""
URL configuration for mypro project.

The `urlpatterns` list routes URLs to views. For more information please see:
    https://docs.djangoproject.com/en/5.2/topics/http/urls/
Examples:
Function views
    1. Add an import:  from my_app import views
    2. Add a URL to urlpatterns:  path('', views.home, name='home')
Class-based views
    1. Add an import:  from other_app.views import Home
    2. Add a URL to urlpatterns:  path('', Home.as_view(), name='home')
Including another URLconf
    1. Import the include() function: from django.urls import include, path
    2. Add a URL to urlpatterns:  path('blog/', include('blog.urls'))
"""
from tkinter.font import names
from .views import GoogleAuthAPIView
from django.contrib import admin
from django.urls import path
from . import views
from django.contrib.auth.views import PasswordResetView,PasswordResetDoneView,PasswordResetConfirmView,PasswordResetCompleteView
from .views import SignupAPIView,LoginAPIView
urlpatterns = [
    path('admin/', admin.site.urls),
    path('Login/',views.Login_view,name='login'),
    path('activation/<str:id>/',views.activation,name='activation'),
    path('signup/',views.signup,name="signup"),
    path('reset/', PasswordResetView.as_view(template_name="pass_reset.html"), name='password_reset'),
    path('password_reset/', PasswordResetDoneView.as_view(template_name="pass_reset_done.html"),
         name='password_reset_done'),
    path('password_confirm/<uidb64>/<token>/',
         PasswordResetConfirmView.as_view(template_name="pass_reset_confirm.html"), name='password_reset_confirm'),
    path('password_complete/', PasswordResetCompleteView.as_view(template_name="complete.html"),
         name='password_reset_complete'),
    path('register/', views.register, name='register'),
    path('admin_panel/',views.admin_panel,name='admin_panel'),
    path('logout/',views.mylogout,name='logout'),
    path('api/send_otp/', views.send_otp, name='send_otp'),
    path('api/verify_otp/',views.verify_otp, name='verify_otp'),
    path('google-login/', views.google_login, name='google_login'),
    path("api/google-auth/", GoogleAuthAPIView.as_view(), name="google_auth"),
    path('api/signup/', SignupAPIView.as_view(), name='signup_api'),
    path('api/login/', LoginAPIView.as_view(), name='login_api'),
]
