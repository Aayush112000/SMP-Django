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
    path("register/",views.UserSignUp.as_view()),
    path("login/",views.UserLogin.as_view()),
    path("logout/",views.UserLogout.as_view()),
    path("forgotpassword/",views.ForgotPasswordView.as_view()),
    path("passwordresetconfirm/reset-password/<str:uidb64>/<str:token>/",views.PasswordResetConfirmView.as_view()),
    path("changepassword/",views.ChangePasswordView.as_view()),
    path("uploadpost/",views.UploadPost.as_view()),
    path("addcomment/",views.AddComment.as_view()),
    path("viewpost/",views.PostView.as_view()),
    path("verifyuser/<str:uidb64>/<str:token>/",views.VerifyRegister.as_view()),
    path("viewuser/",views.UserInfo.as_view()),
    path('make_payment/', views.PaymentAPI.as_view(), name='make_payment'),
    path('create-payment-intent/', views.PaymentIntentView.as_view(), name='create-payment-intent'),
    path('confirm-payment/', views.ConfirmPaymentView.as_view(), name='confirm-payment'),
    path('stripe-webhook/', views.stripe_webhook, name='stripe-webhook'),
]
