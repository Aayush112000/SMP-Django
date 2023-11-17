from django.shortcuts import render
from rest_framework.views import APIView
from rest_framework.response import Response
from .models import *
from utilities.auth_utilities import custom_login_required

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

class PostView(APIView):
    @custom_login_required
    def get(self,request):
        allPosts = Post.objects.all().values().order_by('-id')
        return Response({"Message":"List of Posts", "Post List":allPosts})