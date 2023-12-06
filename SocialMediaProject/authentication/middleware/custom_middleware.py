import jwt
from authentication.models import *
from rest_framework_simplejwt.tokens import AccessToken
from rest_framework.exceptions import AuthenticationFailed
from django.views.decorators.clickjacking import xframe_options_deny
from rest_framework.response import Response
import json
from django.shortcuts import render
from django.http import JsonResponse
import logging

logger = logging.getLogger(__name__)


class CustomJwtAuthenticationMiddleware:
    
    def __init__(self, get_response) -> None:
        self.get_response = get_response
        # print("\n\n",self.get_response)
    

    def __call__(self, request):
        # logging.info('Execution Start')
        logger.info("Execution Start")
        logger.debug(request.path)
        
        exempt_middleware_path_list = ['','/','/admin/','/user/','/user/register/','/user/logout/','/user/login/','/user/forgotpassword/',
                                       '/user/changepassword/','/user/viewuser/']
        start_with_path = ['/admin/','/user/verifyuser/','/user/passwordresetconfirm/reset-password/']
        print(request.path)
        # print(list(request.path.startswith(path) for path in start_with_path))
        
        if request.path in exempt_middleware_path_list or True in list(request.path.startswith(path) for path in start_with_path):
            response = self.get_response(request)
        else:
            auth_header = request.headers.get('Authorization')
            
            if not auth_header:
                response = JsonResponse({"status": 401, "message": "JWT token is missing"})
                logger.info("Execution End")
                return response
            
            secret = "smp"
            decoded_jwt = jwt.decode(auth_header, secret, algorithms=['HS256'])

            if request.POST.get("name") == decoded_jwt.get('name'):
                response = self.get_response(request)
            else:
                response = JsonResponse({"status": 401, "message": "Please Login First..."})
        
        logger.info("Execution End")
        return response