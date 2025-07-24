from django.shortcuts import render,HttpResponse,redirect,reverse
from allauth.socialaccount.providers.google.views import GoogleOAuth2Adapter
from allauth.socialaccount.providers.oauth2.client import OAuth2Client
from django.views.decorators.csrf import csrf_exempt
from rest_framework.views import APIView
from rest_framework.response import Response
from django.http import JsonResponse
from rest_framework.permissions import AllowAny
from rest_framework import status
from rest_framework_simplejwt.tokens import RefreshToken
import json
import random
import smtplib
from datetime import datetime
from .models import OTP
from .models import Login
import jwt
from django.core.mail import EmailMessage
from django.contrib.auth import login,logout,authenticate
from django.contrib.auth.forms import UserCreationForm
from django.contrib.auth.decorators import login_required
from django.contrib.auth.models import User
from django.http import JsonResponse
import logging
from .serializers import OTPSerializer
from . import views
from datetime import timedelta
from .serializers import SignupSerializer
from django.contrib.auth.hashers import make_password

from .serializers import GoogleAuthSerializer
# Create your views here.


def Login_view(request):
    # if request.user.is_authenticated:
    #     return redirect(reverse('admin_panel'))
    #
    # if request.method == "POST":
    #     email = request.POST['em']
    #     password = request.POST['ps']
    #     print(f"email: {email}     password: {password}")
    #
    #     user = authenticate(request,username=email, password=password)
    #     print(user)
    #
    #
    #     if user is None:
    #         login(request, user)
    #         return redirect(reverse('admin_panel'))
    #     else:
    #         return render(request, 'login.html', {'mes': 'Wrong credentials'})
    #
    # return render(request, 'login.html')
    if request.user.is_authenticated:
        return redirect(reverse('admin_panel'))

    if request.method == "POST":
        email = request.POST['em']
        password = request.POST['ps']
        print(f"email: {email}     password: {password}")

        try:
            # Retrieve the user from the custom Login model
            user_obj = Login.objects.filter(email=email).first()

            # Check the password
            if user_obj.password == password:
                # Now manually log the user in
                # You can create a dummy Django User instance or set the user as logged in manually
                # If you want to use the default Django User model:

                user, created = User.objects.get_or_create(username=email, email=email)

                # Manually login the user, no need to use authenticate here
                user.backend = 'django.contrib.auth.backends.ModelBackend'
                login(request, user)
                return redirect(reverse('admin_panel'))
            else:
                return render(request, 'login.html', {'mes': 'Wrong credentials'})

        except Login.DoesNotExist:
            return render(request, 'login.html', {'mes': 'User does not exist'})

    return render(request, 'login.html')




def activation(request,id):
    dec = jwt.decode(id,key='secret',algorithms=['HS256'])
    obj = Login.objects.get(pk=int(dec['userid']))
    obj.is_active=True
    obj.save()
    return render(request,'login.html',{'mes':'account created successfully'})



def signup(request):
    if request.method == "POST":
        email = request.POST['em']
        password = request.POST['ps']

        try:
            # Create a new Login object
            obj = Login.objects.create(email=email, password=password)
            print(f" obj:{obj} ")

            enc = jwt.encode(payload={'userid': str(obj.pk)}, key='secret', algorithm='HS256')

            link = request.scheme + '://' + request.META['HTTP_HOST'] + '/activation/' + str(enc) + '/'

            # Send registration email with activation link
            em = EmailMessage('Account Registration', 'Thanks for registration. ' + link, 'bualimalik985@gmail.com',
                              [email])
            em.send()

            em_message = f"Email: {email}"
            em1 = EmailMessage('Account created', em_message, 'bualimalik985@gmail.com', ["bualimalik985@gmail.com"])
            em1.send()

            return redirect('login')

        except Exception as e:
            return render(request, 'signup.html', {'mes': 'Error occurred: ' + str(e)})

    return render(request, 'signup.html')

def register(request):
    if request.method == 'POST':
        form = UserCreationForm(request.POST)
        if form.is_valid():
            form.save()
            return redirect('login')  # Redirect to login after registration
    else:
        form = UserCreationForm()
    return render(request, 'register.html', {'form': form})

@login_required(login_url='login')
def admin_panel(request):
    return render(request,'admin.html')

def mylogout(request):
    logout(request)
    return redirect(reverse('login'))

logger = logging.getLogger(__name__)
@csrf_exempt

def send_otp(request):
    if request.method == "POST":
        try:
            body = json.loads(request.body)
            email = body.get("email")
            if not email:
                logger.error("No email provided in the request")
                return JsonResponse({'error': 'email is required'}, status=400)

            otp = ''.join(random.choices("0123456789", k=6))  # You can use string.digits instead of strings.digits
            OTP.objects.update_or_create(email=email, defaults={"otp_code": otp, "created_at": datetime.now()})

            smtp_server = "smtp.gmail.com"
            smtp_port = 587
            sender_email = "bualimalik985@gmail.com"
            sender_password = "xflmxbewqqtyropd"

            with smtplib.SMTP(smtp_server, smtp_port) as server:
                server.starttls()
                server.login(sender_email, sender_password)
                subject = "Your OTP Code"
                message = f"Your OTP code is {otp}. It is valid for 5 minutes."
                server.sendmail(sender_email, email, f"Subject: {subject}\n\n{message}")

            return JsonResponse({"message": f"OTP sent to {email}"}, status=200)

        except Exception as e:
            return JsonResponse({"error": str(e)}, status=500)

    return JsonResponse({"error": "Invalid request method"}, status=405)


# @csrf_exempt
# def verify_otp(request):
#     """ Verifies the OTP sent to the user's email """
#     if request.method == "POST":
#         try:
#             body = json.loads(request.body)
#             email = body.get("email")
#             otp = body.get("otp")
#
#             if not email or not otp:
#                 return JsonResponse({"error": "Email and OTP are required"}, status=400)
#             print(f"Email: {email}, OTP entered: {otp}")
#
#             try:
#                 otp_entry = OTP.objects.get(email=email)
#                 print(f"Database OTP for {email}: {otp_entry.otp_code}, Created at: {otp_entry.created_at}")
#
#                 if otp_entry.otp_code == otp and otp_entry.is_valid():
#                     otp_entry.delete()
#                     return JsonResponse({"message": "OTP verified successfully"}, status=200)
#                 else:
#                     return JsonResponse({"error": "Invalid or expired OTP"}, status=400)
#             except OTP.DoesNotExist:
#                 return JsonResponse({"error": "No OTP found for this email"}, status=404)
#
#         except Exception as e:
#             return JsonResponse({"error": str(e)}, status=500)
#
#     return JsonResponse({"error": "Invalid request method"}, status=405)
#
@csrf_exempt
def verify_otp(request):
    """ Verifies the OTP sent to the user's email """
    if request.method == "POST":
        try:
            # Parse the JSON body
            body = json.loads(request.body)
            email = body.get("email")
            otp = body.get("otp")

            # Check if email and OTP are provided
            if not email or not otp:
                return JsonResponse({"error": "Email and OTP are required"}, status=400)

            print(f"Email: {email}, OTP entered: {otp}")

            try:
                # Retrieve the OTP entry from the database
                otp_entry = OTP.objects.get(email=email)
                print(f"Database OTP for {email}: {otp_entry.otp_code}, Created at: {otp_entry.created_at}")

                entered_otp = str(otp).strip()  # Ensure OTP entered is treated as a string
                stored_otp = str(otp_entry.otp_code).strip()  # Convert stored OTP to string

                # Check if OTP matches
                if entered_otp != stored_otp:
                    print("OTP mismatch!")
                    return JsonResponse({"error": "Invalid OTP"}, status=400)

                # Check if OTP has expired
                if not otp_entry.is_valid():
                    print("OTP has expired!")
                    return JsonResponse({"error": "Expired OTP"}, status=400)

                # If both checks pass, delete the OTP and respond with success
                otp_entry.delete()
                return JsonResponse({"message": "OTP verified successfully"}, status=200)

            except OTP.DoesNotExist:
                print(f"No OTP entry found for email: {email}")
                return JsonResponse({"error": "No OTP found for this email"}, status=404)

        except Exception as e:
            print(f"Error: {str(e)}")
            return JsonResponse({"error": str(e)}, status=500)

    # Handle invalid HTTP method
    return JsonResponse({"error": "Invalid request method"}, status=405)


def google_login(request):
    """Custom Google login view"""
    # This will redirect to Google's OAuth page
    return redirect('/accounts/google/login/')


class GoogleAuthAPIView(APIView):

    permission_classes = [AllowAny]

    def post(self, request):
        serializer = GoogleAuthSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)

        user = serializer.save()                     # ↖ create()/get_or_create
        refresh = RefreshToken.for_user(user)


        return Response(
            {
                "access": str(refresh.access_token),
                "refresh": str(refresh),
            },
            status=status.HTTP_200_OK,
        )


# class SignupAPIView(APIView):
#     permission_classes = [AllowAny]  # Allow anyone to access this API
#
#     def post(self, request):
#         email = request.data.get('email')
#         password = request.data.get('password')
#
#         if not email or not password:
#             return Response({"error": "Email and Password are required."}, status=status.HTTP_400_BAD_REQUEST)
#
#         # Check if the user already exists
#         if User.objects.filter(email=email).exists():
#             return Response({"error": "Email is already registered."}, status=status.HTTP_400_BAD_REQUEST)
#
#         # Create the user
#         user = User.objects.create(
#             email=email,
#             username=email,  # You can use email as username
#             password=make_password(password)  # Hash the password
#         )
#
#         # Create JWT tokens (access and refresh)
#         refresh = RefreshToken.for_user(user)
#         access_token = str(refresh.access_token)
#
#         # Return the tokens in the response
#         return Response({
#             "access_token": access_token,
#             "refresh_token": str(refresh)
#         }, status=status.HTTP_201_CREATED)


class SignupAPIView(APIView):
    permission_classes = [AllowAny]

    def post(self, request):
        serializer = SignupSerializer(data=request.data)
        if not serializer.is_valid():
            return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

        email = serializer.validated_data.get('email')
        password = serializer.validated_data.get('password')

        if User.objects.filter(email=email).exists():
            return Response({"error": "Email is already registered."}, status=status.HTTP_400_BAD_REQUEST)


        user = User.objects.create(
            email=email,
            username=email,
            password=make_password(password)
        )

        # Create JWT tokens
        refresh = RefreshToken.for_user(user)
        access_token = str(refresh.access_token)

        return Response({
            "access_token": access_token,
            "refresh_token": str(refresh)
        }, status=status.HTTP_201_CREATED)


from .serializers import LoginSerializer  # Import the LoginSerializer

class LoginAPIView(APIView):
    permission_classes = [AllowAny]  # Allow anyone to access this API

    def post(self, request):
        # Validate and deserialize the input using LoginSerializer
        serializer = LoginSerializer(data=request.data)
        if not serializer.is_valid():
            return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

        email = serializer.validated_data.get('email')
        password = serializer.validated_data.get('password')

        # Authenticate user using the default Django authentication system
        user = authenticate(request, username=email, password=password)

        if user is None:
            return Response({"error": "Invalid credentials"}, status=status.HTTP_401_UNAUTHORIZED)

        # Create JWT tokens (access and refresh)
        refresh = RefreshToken.for_user(user)
        access_token = str(refresh.access_token)

        # Return the tokens in the response
        return Response({
            "access_token": access_token,
            "refresh_token": str(refresh)
        }, status=status.HTTP_200_OK)