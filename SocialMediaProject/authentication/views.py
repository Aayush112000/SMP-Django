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

# Create your views here.
class UserApiView(APIView):
    @custom_login_required
    def get(self,request):
        
        allUsers = User.objects.all().values()
        return Response({"Message":"List of Users", "User List":allUsers})
    
    def post(self, request):
        
        User.objects.create(name = request.data["name"],
                            email = request.data['email'],
                            password = request.data["password"],
                            is_validate = request.data["is_validate"],
                            )
        
        user = User.objects.filter(name=request.data['name']).values()
        return Response({"Message":"New User Added", "User":user})


#user sign up
class UserSignUp(APIView):
    def post(self, request):
        name = request.data['name']
        email = request.data['email']
        password = request.data["password"]

        try:
            if User.objects.all().get(name=name):
                return Response({'message':'Username Not Available'})
        except:
            pass

        try:
            if User.objects.all().get(email=email):
                return Response({'message':'This email is already registered'})
        except:
            pass

        new_user = User.objects.create(name=name,email=email,password=password)
        new_user.is_validate = True
        new_user.save()
        return Response({'message':'registraion Successfull'})
        # messages.success(request,"registraion Successfull")

engine = create_engine('postgresql+psycopg2://postgres:1234@localhost:5432/SMP', echo=True)

conn = engine.connect()

#user login
class UserLogin(APIView):
    def post(self, request):
        email = request.data.get("email")
        password = request.data.get("password")

        # user = authenticate(email=email,password=password)

        #For fatch data from database (will get DATA-Frame)
        data = pd.read_sql("SELECT * from  authentication_user",conn)

        # Check with database's password for authenticate
        users = data.loc[:,['email','password']]
        if email in list(data['email']):
            pass1 = users.loc[users["email"]==email]["password"]

            if pass1.iloc[0] == password:
                return Response({'message':'successful logged in'})
            else:
                return Response({'message':'Incorrect username or password'})
        else:
            return Response({'message':'Incorrect username'})

#logout user
class UserLogout(APIView):
    def get(self,request):
        logout(request)
        return Response({'message':'Logged out successfully'})

#Forgot Password
class ForgotPasswordView(APIView):
    def post(self, request):
        email = request.data.get('email')

        try:
            user = User.objects.get(email=email)
        except User.DoesNotExist:
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

        return Response({'message': 'Password reset email sent'}, status=status.HTTP_200_OK)

#Redirect from Email link
class PasswordResetConfirmView(APIView):
    def post(self, request, uidb64, token):
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
            return Response({'message': 'Password reset successful'}, status=status.HTTP_200_OK)
        else:
            return Response({'error': 'Invalid token'}, status=status.HTTP_400_BAD_REQUEST)

# Change Password
class ChangePasswordView(APIView):
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
                return Response({'message':'Password change successfully'})
            else:
                return Response({'message':'Incorrect email or Old password'})
        else:
            return Response({'message':'Incorrect username'})

#post upload
class UploadPost(APIView):
    @custom_login_required
    def post(self, request):
        title1 = pd.read_sql("SELECT title from  authentication_post",conn)
        title1 = title1["title"]
        lst = []
        for t in title1:
            lst.append(t)

        email = request.data.get("email")
        user = User.objects.get(email=email)

        title = request.data.get('title')
        if title in lst:
            return Response({'message':'This title already used'})

        image = request.FILES.get('image')
        likes_list = request.data.get('likes')
        likes_list = list(likes_list.split(","))

        # new_post = Post.objects.create(user=user,title=title,image=image,likes=likes)
        new_post = Post.objects.create(user=user,title=title,image=image)
        new_post.save()

        for id in likes_list:
            like_user = User.objects.get(id=id)
            new_post.likes.add(like_user)
        new_post.save()

        return Response({'message':'Post Added Successfully'})

#ADD Comment
class AddComment(APIView):
    @custom_login_required
    def post(self, request):
        title = request.data.get("title")
        post = Post.objects.get(title=title)
        email = request.data.get("email")
        user = User.objects.get(email=email)
        content = request.data.get("content")
        comments_like = request.data.get("comments_like")
        comments_like = list(comments_like.split(","))

        reply = request.data.get("reply")

        new_comment = Comment.objects.create(post=post,user=user,content=content,reply=reply)
        new_comment.save()
        for id in comments_like:
            like_user = User.objects.get(id=id)
            new_comment.comments_like.add(like_user)
        new_comment.save()

        return Response({'message':'Comment Added Successfully'})
    
#Get All posts
class PostView(APIView):
    @custom_login_required
    def get(self,request):
        allPosts = Post.objects.all().values().order_by('-id')
        return Response({"Message":"List of Posts", "Post List":allPosts})