from django.contrib.auth.backends import BaseBackend
from memento.models import CustomUser
import requests
from hashlib import sha256
import os


REST_base_url = os.environ.get("MEMENTO_FLASK_URL")
WHITE_LISTED_HEADERS = {'x-access-token' : os.environ.get("MEMENTO_FLASK_WHITE_LISTED_TOKEN") }


class RESTBackend(BaseBackend):
    def authenticate(self, request, username=None, password=None):
        response = requests.get(REST_base_url + '/users/byusername/' + username, headers=WHITE_LISTED_HEADERS)
        if (response.status_code != 404):
            user_data = response.json()
            if (sha256(password.encode('utf-8')).hexdigest() == user_data['user']['password']):
                try:
                    user = CustomUser.objects.get(username=username)
                    user.update_info(user_data['user']['user_id'], user_data['user']['username'], user_data['user']['name'],
                                     user_data['user']['email'], user_data['user']['settings'], user_data['user']['password'])
                    user.save()
                except CustomUser.DoesNotExist:
                    CustomUser.objects.filter(user_id=user_data['user']['user_id']).delete()
                    user = CustomUser.objects.create_user(user_data['user']['user_id'], user_data['user']['username'], user_data['user']['name'],
                                                          user_data['user']['email'], user_data['user']['settings'], user_data['user']['password'])
                    user.is_staff = False
                    user.is_superuser = False
                    user.save()
                return user
        return None

    def get_user(self, username):
        try:
            return CustomUser.objects.get(pk=username)
        except CustomUser.DoesNotExist:
            return None
