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
import json
import logging

# from .seriallizer import *
# from .emails import *
# from rest_framework.views import APIView
# from rest_framework.response import Response
# from re import S
# from tkinter import E


logger = logging.getLogger(__name__)

engine = create_engine('postgresql+psycopg2://postgres:1234@localhost:5432/SMP', echo=True)

conn = engine.connect()

# Custom Login Required
def custom_login_required(view_func):
    def wrapper(request, *args, **kwargs):

        logger.info("Execution Start")
        data = pd.read_sql("SELECT * from  authentication_user",conn)
        email = request.data.get('email')
        password = request.data.get('password')

        # email = request.POST['email']
        # password = request.POST['password']

        # print("\n\n",email," : ",password)
    
        if email and password:
            users = data.loc[:,['email','password']]
            if email in list(data['email']):
                pass1 = users.loc[users["email"]==email]["password"]
                if pass1.iloc[0] == password:
                    return view_func(request, *args, **kwargs)
        raise PermissionDenied(detail='Authentication required')
    logger.info("Execution End")
    return wrapper

