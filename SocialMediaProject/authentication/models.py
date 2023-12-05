from django.db import models
from django.utils import timezone
# from PIL import Image
# from django import forms
# from django.utils.translation import ugettext_lazy as _

# from django.contrib.postgres.fields import JSONField
from django.db.models import JSONField

# Create your models here.
class User(models.Model):
    name = models.CharField(max_length=200)
    email = models.EmailField(max_length=254)
    password = models.CharField(max_length=20)
    created_at=  models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    is_validate = models.BooleanField(default=False)
    last_login = models.DateTimeField(auto_now=True)
    jwt_token = models.CharField(max_length=200,default="")
    is_verified = models.BooleanField(default=False)

    def get_email_field_name(self):
        return 'email'

    def __str__(self):
        return self.name
    
    def set_password(self,password):
        self.password = password

class Post(models.Model):
    user = models.ForeignKey(User, on_delete=models.CASCADE)
    title = models.CharField(max_length=100)
    image = models.ImageField(upload_to ='uploads/')
    likes = models.ManyToManyField(User,related_name="Likes",blank=True)
    date_posted = models.DateTimeField(default=timezone.now)

    def __str__(self):
        return f'{self.user.name}\'s Post- Title : {self.title}  likes : {self.likes_count()}'

    def likes_count(self):
        return self.likes.count()

class Comment(models.Model):
    post = models.ForeignKey(Post, on_delete=models.CASCADE, related_name="comments")
    user = models.ForeignKey(User, on_delete=models.CASCADE)
    content = models.TextField()
    comments_like = models.ManyToManyField(User,related_name="Comment_Likes",blank=True)
    timestamp = models.DateTimeField(auto_now_add=True)
    reply = JSONField(default=dict)

    def __str__(self):
        return f'commet on {self.post.user.name}\'s {self.post.title} post by {self.user.name} likes : {self.comment_likes_count()}'

    def comment_likes_count(self):
        return self.comments_like.count()