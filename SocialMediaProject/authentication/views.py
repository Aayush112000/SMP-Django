from django.shortcuts import render
from rest_framework.views import APIView
from rest_framework.response import Response
from .models import *

# Create your views here.
class UserApiView(APIView):
    def get(self,request):
        
        allUsers = User.objects.all().values()
        return Response({"Message":"List of Users", "USer List":allUsers})
    
    def post(self, request):
        
        User.objects.create(name = request.data["name"],
                            email = request.data['email'],
                            password = request.data["password"],
                            is_validate = request.data["is_validate"],
                            )
        
        user = User.objects.filter(name=request.data['name']).values()
        return Response({"Message":"New User Added", "User":user})
