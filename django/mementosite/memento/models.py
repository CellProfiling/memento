from django.db import models
from django.contrib.auth.models import BaseUserManager, AbstractBaseUser, PermissionsMixin
from django.utils import timezone


class CustomUserManager(BaseUserManager):
    def create_user(self, user_id, username, name, email, settings, password):
        user = self.model(user_id=user_id, username=username, name=name, email=email, settings=settings)
        user.set_password(password)
        user.save(using=self._db)
        return user

    def create_superuser(self, user_id, username, name, email, settings, password):
        user = self.create_user(user_id=user_id, username=username, name=name, email=email, settings=settings, password=password)
        user_is_admin = True
        user.save(using=self._db)

        return user


class CustomUser(AbstractBaseUser, PermissionsMixin):
    user_id = models.IntegerField(default=0, unique=True)
    username = models.CharField(max_length=50, unique=True)
    name = models.CharField(max_length=255)
    email = models.CharField(max_length=255)
    settings = models.CharField(max_length=1000)
    is_active = models.BooleanField(default=True)
    is_staff = models.BooleanField(default=False)
    is_admin = models.BooleanField(default=False)

    objects = CustomUserManager()

    USERNAME_FIELD = 'username'
    EMAIL_FIELD = 'email'
    REQUIRED_FIELDS = ['user_id', 'name', 'email', 'settings']

    def __str__(self):
        return self.username

    def has_perm(self, perm, obj=None):
        return True

    def has_module_perms(self, app_label):
        return True

    def update_info(self, user_id, username, name, email, settings, password):
        self.user_id = user_id
        self.username = username
        self.name = name
        self.email = email
        self.settings = settings
        self.set_password(password)
