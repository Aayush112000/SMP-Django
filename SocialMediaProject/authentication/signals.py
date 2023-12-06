from django.db.models.signals import post_save, pre_delete
from django.dispatch import receiver
from .models import Profile,User
import requests

@receiver(post_save,sender=User)
def create_user_profile(sender,instance,created,**kwargs):
    if created:
        print(f"instance --> {instance}")
        
        Profile.objects.create(user=instance)
        api_url = "http://127.0.0.1:8000/user/viewuser/"
        json_data = {'name': instance.name}

        # Send a GET request to the API with JSON data
        response = requests.get(api_url, json=json_data)

        # Process the API response as needed
        if response.status_code == 200:
            print("\n\n\n\n\n",response.text)
        else:
            print("\n\n\n\n\n",f"Error: {response.status_code}\n{response.text}")

@receiver(post_save, sender=User)
def save_user_profile(sender, instance, **kwargs):
    instance.profile.save()