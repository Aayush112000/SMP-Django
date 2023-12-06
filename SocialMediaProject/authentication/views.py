from django.shortcuts import render
from rest_framework.views import APIView
from rest_framework.response import Response
from .models import *
from utilities.auth_utilities import custom_login_required

from django.shortcuts import render ,redirect
from django.http import HttpResponse , HttpResponseRedirect
from authentication.models import User,Post,Comment
from django.contrib import messages
from django.contrib.auth import authenticate,login,logout
from rest_framework.exceptions import AuthenticationFailed
# from django.contrib.auth.models import User
from django.contrib.auth.decorators import login_required
from rest_framework.response import Response
from rest_framework.views import APIView

import datetime

from sqlalchemy import create_engine, ForeignKey, Column,String, Integer, CHAR
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker

import pandas as pd

from django.contrib.auth.tokens import default_token_generator
from django.utils.encoding import force_bytes
from django.utils.http import urlsafe_base64_encode
from django.core.mail import send_mail
from django.conf import settings
from rest_framework import status

from django.utils.encoding import force_str
from django.utils.http import urlsafe_base64_decode
from rest_framework.exceptions import PermissionDenied
from django.http import HttpRequest, QueryDict
from django.http import JsonResponse
import json

import jwt
import logging

logger = logging.getLogger(__name__)


# Create your views here.
class UserApiView(APIView):
    # @custom_login_required
    def get(self,request):
        logging.info('View User :Execution Start')
        logger.info("View User :Execution Start")

        allUsers = User.objects.all().values()
        logger.info("View ALL User :Execution End")
        return Response({"Message":"List of Users", "User List":allUsers})
    
    def post(self, request):
        
        User.objects.create(name = request.data["name"],
                            email = request.data['email'],
                            password = request.data["password"],
                            is_validate = request.data["is_validate"],
                            )
        
        user = User.objects.filter(name=request.data['name']).values()
        return Response({"Message":"New User Added", "User":user})

# Create your views here.
class UserInfo(APIView):
    def get(self,request):
        user = User.objects.get(name = request.data.get("name"))

        return Response({"Message":"User data ", "User name":user.name,"User email":user.email})


#user sign up
class UserSignUp(APIView):
    def post(self, request):
        logger.info("Register User :Execution Start")
        name = request.data['name']
        email = request.data['email']
        password = request.data["password"]

        # header = {  
        #         "alg": "HS256",  
        #         "typ": "JWT"  
        #         }
        
        # payload = {  
        #         "name": name
        #         }
        
        # secret = "smp"

        # encoded_jwt = jwt.encode(payload, secret, algorithm='HS256', headers=header)
        # print(encoded_jwt)  
        # decoded_jwt = jwt.decode(encoded_jwt, secret, algorithms=['HS256'])  
        # print(decoded_jwt)

        try:
            if User.objects.all().get(name=name):
                logger.error("RegisterUser : msg : {Username Not Available}")
                return Response({'message':'Username Not Available'})
        except:
            pass

        try:
            if User.objects.all().get(email=email):
                logger.error("RegisterUser : msg : {This email is already registered}")
                return Response({'message':'This email is already registered'})
        except:
            pass

        new_user = User.objects.create(name=name,email=email,password=password)
        new_user.is_validate = True
        new_user.save()

        # try:
        #     user = User.objects.get(email=email)
        # except User.DoesNotExist:
        #     return Response({'error': 'User not found'}, status=status.HTTP_404_NOT_FOUND)
        
        token = default_token_generator.make_token(new_user)
        uidb64 = urlsafe_base64_encode(force_bytes(new_user.pk))

        register_link = f"{settings.REGISTER_URL}/{uidb64}/{token}/"

        # Send reset email
        send_mail(
            'Verify Register',
            f'Click the link below to Register:\n\n{register_link}',
            settings.EMAIL_HOST_USER,
            [new_user.email],
            fail_silently=False,
        )
        logger.info(f"Register User :Execution End and Send mail on {new_user.email} for Verification")
        return Response({'message': 'Register verification link sent on your Email'}, status=status.HTTP_200_OK)

        # if payload["name"]==decoded_jwt["name"]:
        # return Response({'message':"Register and Login successfully"})
        # else:
        #     return Response({'message':'registraion Successfull'})
        # messages.success(request,"registraion Successfull")

engine = create_engine('postgresql+psycopg2://postgres:1234@localhost:5432/SMP', echo=True)

conn = engine.connect()

class VerifyRegister(APIView):
    def get(self, request, uidb64, token):
        logger.info("Register User :Execution Start")
        try:
            uid = force_str(urlsafe_base64_decode(uidb64))
            user = User.objects.get(pk=uid)
        except (TypeError, ValueError, OverflowError, User.DoesNotExist):
            user = None

        if user is not None and default_token_generator.check_token(user, token):
            
            header = {  
                "alg": "HS256",  
                "typ": "JWT"  
                }
        
            payload = { 
                    "id":user.id,
                    "name": user.name
                    }
            
            secret = "smp"

            encoded_jwt = jwt.encode(payload, secret, algorithm='HS256', headers=header)

            user.jwt_token = encoded_jwt
            user.is_verified = True
            user.save()
            logger.info("Verify User : Registration verify successful & login done!")
            return Response({'message': 'Registration verify successful & login done!'}, status=status.HTTP_200_OK)
        else:
            logger.error("Verify User Error : Invalid token")
            return Response({'error': 'Invalid token'}, status=status.HTTP_400_BAD_REQUEST)

#user login
class UserLogin(APIView):
    def post(self, request):
        logger.info("Login User :Execution Start")
        name = request.data.get('name')
        email = request.data.get("email")
        password = request.data.get("password")

        header = {  
                "alg": "HS256",  
                "typ": "JWT"  
                }
        
        payload = {  
                "name": name
                }
        
        secret = "smp"

        encoded_jwt = jwt.encode(payload, secret, algorithm='HS256', headers=header)
        # print(encoded_jwt)

        usr = User.objects.get(email=email)

        #For fatch data from database (will get DATA-Frame)
        data = pd.read_sql("SELECT * from  authentication_user",conn)

        # Check with database's password for authenticate
        users = data.loc[:,['email','password']]
        if email in list(data['email']):
            pass1 = users.loc[users["email"]==email]["password"]

            if pass1.iloc[0] == password:
                usr.jwt_token = encoded_jwt
                usr.save()
                logger.info("Login User : successful logged in")
                return Response({'message':'successful logged in'})
            else:
                logger.error("Login User Error : Incorrect username or password")
                return Response({'message':'Incorrect username or password'})
        else:
            logger.error("Login User name Error : Incorrect username")
            return Response({'message':'Incorrect username'})

#logout user
class UserLogout(APIView):
    def get(self,request):
        logger.info("Logout User :Execution Start")
        name = request.data.get('name')
        # email = request.data.get("email")
        usr = User.objects.get(name=name)
        usr.jwt_token=""
        usr.save()
        logout(request)
        logger.info("Logout User : Logged out successfully")
        return Response({'message':'Logged out successfully'})

#Forgot Password
class ForgotPasswordView(APIView):
    def post(self, request):
        logger.info("Forgot Password :Execution Start")
        email = request.data.get('email')

        try:
            user = User.objects.get(email=email)
        except User.DoesNotExist:
            logger.error("Forgot Password Error : User not found")
            return Response({'error': 'User not found'}, status=status.HTTP_404_NOT_FOUND)
        
        token = default_token_generator.make_token(user)
        uidb64 = urlsafe_base64_encode(force_bytes(user.pk))

        reset_link = f"{settings.FRONTEND_URL}/reset-password/{uidb64}/{token}/"

        # Send reset email
        send_mail(
            'Password Reset',
            f'Click the link below to reset your password:\n\n{reset_link}',
            settings.EMAIL_HOST_USER,
            [user.email],
            fail_silently=False,
        )

        logger.info("Forgot Password :Password reset email sent")
        return Response({'message': 'Password reset email sent'}, status=status.HTTP_200_OK)

#Redirect from Email link
class PasswordResetConfirmView(APIView):
    def post(self, request, uidb64, token):
        logger.info("Password Reset Confirm :Execution Start")
        try:
            uid = force_str(urlsafe_base64_decode(uidb64))
            user = User.objects.get(pk=uid)
        except (TypeError, ValueError, OverflowError, User.DoesNotExist):
            user = None

        if user is not None and default_token_generator.check_token(user, token):
            # Valid token, update the password
            new_password = request.data.get('new_password')
            user.set_password(new_password)
            user.save()
            logger.info("Password Reset Confirm : Password reset successful")
            return Response({'message': 'Password reset successful'}, status=status.HTTP_200_OK)
        else:
            logger.error("Password Reset Error: Invalid token")
            return Response({'error': 'Invalid token'}, status=status.HTTP_400_BAD_REQUEST)

# Change Password
class ChangePasswordView(APIView):
    logger.info("Change Password :Execution Start")
    def post(self, request):
        email = request.data.get("email")
        old_password = request.data.get("old_password")
        new_password = request.data.get("new_password")

        data = pd.read_sql("SELECT * from  authentication_user",conn)

        users = data.loc[:,['email','password']]

        if email in list(data['email']):
            user = User.objects.get(email=email)
            pass1 = users.loc[users["email"]==email]["password"]

            if pass1.iloc[0] == old_password:
                user.password = new_password
                user.save()
                # user.set_password(new_password)
                # print(user.name,new_password,old_password)
                logger.info("Change Password : Password change successfully")
                return Response({'message':'Password change successfully'})
            else:
                logger.error("Change Password Erro : Incorrect email or Old password")
                return Response({'message':'Incorrect email or Old password'})
        else:
            return Response({'message':'Incorrect username'})

#post upload
class UploadPost(APIView):
    # @custom_login_required
    def post(self, request):
        logger.info("Upload Post :Execution Start")
        # data_str = list((dict(request.POST).keys()))[0]
        # data_dict = json.loads(data_str)

        title1 = pd.read_sql("SELECT title from  authentication_post",conn)
        title1 = title1["title"]
        lst = []
        for t in title1:
            lst.append(t)

        email = request.POST.get("email")
        user = User.objects.get(email=email)

        title = request.POST.get('title')
        if title in lst:
            logger.error("Upload Post : This title already used")
            return Response({'message':'This title already used'})

        image = request.FILES.get('image')
        likes_list = request.POST.get('likes')
        likes_list = list(likes_list.split(","))

        # new_post = Post.objects.create(user=user,title=title,image=image,likes=likes)
        new_post = Post.objects.create(user=user,title=title,image=image)
        new_post.save()

        for id in likes_list:
            like_user = User.objects.get(id=id)
            new_post.likes.add(like_user)
        new_post.save()

        logger.info("Upload Post : Post Added Successfully")
        return Response({'message':'Post Added Successfully'})

# def add_comment_view(request):
#     response = HttpResponse("Your response content")
#     response['X-Frame-Options'] = 'DENY'
#     return response

#ADD Comment
class AddComment(APIView):
    # @custom_login_required
    def post(self, request):
        logger.info("Add Comment : Execution Start")
        # data_str = list((dict(request.POST).keys()))[0]
        # data_dict = json.loads(data_str)
        # data_dict = dict(request.GET)
        # request = JsonResponse(data_dict)
        # print(request)

        # content = request.content.decode('utf-8')  # Decode bytes to string
        # data = json.loads(content)

        # Now 'data' contains the JSON content


        # raw_data = request.body.decode('utf-8')
        # form_data = dict(item.split('=') for item in raw_data.split('&'))

        # print("\n\n -->  ",form_data.get("title"))

        # print("\n\n",request.data)
        # print("\n\n\n","Success....................................")
        title = request.POST.get("title")
        # print("\n\n\n","Success2....................................",title)

        post = Post.objects.get(title=title)
        email = request.POST.get("email")
        user = User.objects.get(email=email)
        content = request.POST.get("content")
        comments_like = request.POST.get("comments_like")
        comments_like = list(comments_like.split(","))

        print("\n\n\n",title)

        reply = request.POST.get("reply")

        new_comment = Comment.objects.create(post=post,user=user,content=content,reply=reply)
        new_comment.save()
        for id in comments_like:
            like_user = User.objects.get(id=id)
            new_comment.comments_like.add(like_user)
        new_comment.save()

        logger.info("Add Comment : Comment Added Successfully")
        return Response({'message':'Comment Added Successfully'})

#Get All posts
class PostView(APIView):
    # @custom_login_required
    def post(self,request):
        logger.info("Post View : Execution Start")
        allPosts = Post.objects.all().values().order_by('-id')
        logger.info("Post View : View all List of Posts")
        return Response({"Message":"List of Posts", "Post List":allPosts})