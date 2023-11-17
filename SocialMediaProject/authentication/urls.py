from django.contrib import admin
from django.urls import path,include
from django.urls import re_path as url
from authentication import views
from utilities.auth_utilities import *

from django.conf import settings
from django.conf.urls.static import static

# This is for save image field's data
urlpatterns = []
if settings.DEBUG:
        urlpatterns += static(settings.MEDIA_URL,
                              document_root=settings.MEDIA_ROOT)

urlpatterns = [
    path("", views.UserApiView.as_view()),
    path("register/",UserSignUp.as_view()),
    path("login/",UserLogin.as_view()),
    path("logout/",UserLogout.as_view()),
    path("forgotpassword/",ForgotPasswordView.as_view()),
    path("passwordresetconfirm/reset-password/<str:uidb64>/<str:token>/",PasswordResetConfirmView.as_view()),
    path("changepassword/",ChangePasswordView.as_view()),
    path("uploadpost/",UploadPost.as_view()),
    path("addcomment/",AddComment.as_view()),
    path("viewpost/",views.PostView.as_view()),
]
