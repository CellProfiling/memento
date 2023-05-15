from django.shortcuts import render, redirect

from django.conf import settings
from django.contrib.auth.decorators import login_required
from django.contrib.auth.forms import AuthenticationForm, authenticate
from django.contrib.auth import login, logout
from django.contrib.staticfiles.storage import staticfiles_storage
from django.http import HttpResponse, HttpResponseRedirect
from django.urls import reverse
from django.utils.html import escape
from html import unescape
import json
import os
from PIL import Image
import random
import requests
import string
from memento.forms import *
from memento import views
from memento.models import CustomUser


REST_base_url = os.environ.get("MEMENTO_FLASK_URL") + '/'
WHITE_LISTED_HEADERS = {'x-access-token' : os.environ.get("MEMENTO_FLASK_WHITE_LISTED_TOKEN") }


def requestAPI(username, method, params, payload=None, headers=None):
    print("request API", username, ":" , method,params)
    if method == "POST":
        return requests.post(REST_base_url + params, json=payload, headers=(WHITE_LISTED_HEADERS if headers is None else headers))
    elif method == "PUT":
        return requests.put(REST_base_url + params, json=payload, headers=(WHITE_LISTED_HEADERS if headers is None else headers))
    elif method == "DELETE":
        return requests.delete(REST_base_url + params, headers=(WHITE_LISTED_HEADERS if headers is None else headers))
    else:
        return requests.get(REST_base_url + params, headers=(WHITE_LISTED_HEADERS if headers is None else headers))

def checkPermissions(permissions_list, min_type, min_level, project_id, category_id, annotation_id):
    is_allowed = False
    for permission in permissions_list:
        if (min_type == 'sysadm'):
            if (permission['type'] == 'sysadm'):
                is_allowed = True
                break
        elif (min_type == 'proadm'):
            if (permission['type'] == 'proadm' or permission['type'] == 'sysadm'):
                is_allowed = True
                break
        else:
            if (permission['type'] == 'sysadm'):
                is_allowed = True
                break
            elif (permission['type'] == 'proown' and permission['type_id'] == project_id):
                is_allowed = True
                break
            elif (project_id != None and permission['type_id'] == project_id and (permission['type'] == ('pro' + min_level) or permission['type'] == 'propar')):
                is_allowed = True
                break
            elif (category_id != None and permission['type_id'] == category_id and (permission['type'] == ('cat' + min_level) or permission['type'] == 'catpar')):
                is_allowed = True
                break
            elif (annotation_id != None and permission['type_id'] == annotation_id and (permission['type'] == ('ann' + min_level) or permission['type'] == 'annpar')):
                is_allowed = True
                break

    return is_allowed


def return_message(request, message, submessages, message_status, next_actions):
    context = {}
    context['message'] = message
    context['submessages'] = submessages
    context['message_status'] = message_status
    context['next_actions'] = next_actions
    return render(request, 'memento/message.html', context)


def return_message_content(request, message, submessages, message_status, next_actions):
    context = {}
    context['message'] = message
    context['submessages'] = submessages
    context['message_status'] = message_status
    context['next_actions'] = next_actions
    return render(request, 'memento/message_content.html', context)


def login_user(request):
    if request.user.is_authenticated:
        return redirect('/memento')
    if request.method == 'GET':
        form = AuthenticationForm()
        context = {'form': form}
        return render(request, 'memento/login.html', context)
    if request.method == 'POST':
        form = AuthenticationForm(request=request, data=request.POST)
        if form.is_valid():
            username = form.cleaned_data.get('username')
            password = form.cleaned_data.get('password')
            user = authenticate(request=request, username=username, password=password)
            if user is not None:
                login(request, user)
                request.session.set_expiry(3600)
                return redirect('/memento')
            else:
                print('User not found')
        else:
            context = {'form': form}
            return render(request, 'memento/login.html', context)


def logout_user(request):
    user = request.user
    not_anonymous = user.is_authenticated
    logout(request)
    if (not_anonymous):
        user.delete()
    form = AuthenticationForm()
    context = {'form': form}
    return render(request, 'memento/login.html', context)


@login_required
def home(request):
    request.session['permissions'] = []
    request.session['settings'] = {}

    context = {}
    response = requestAPI(request.user.username, "GET", 'permissions/byfilter/' + str(request.user.user_id) + '/none/0')
    if (response.status_code != 404):
        permissions_data = response.json()
        permissions_list = []
        for curr_permission in permissions_data['permissions']:
            permissions_list.append({ 'type': curr_permission['type'], 'type_id': curr_permission['type_id']})
        if (request.user.settings and request.user.settings != ''):
            request.session['settings'] = dict(item.split(":") for item in request.user.settings.split(","))
        is_sysadm = any('sysadm' in permission['type'] for permission in permissions_list)
        is_proadm = any('proadm' in permission['type'] for permission in permissions_list)
        context['is_sysadm'] = is_sysadm
        context['is_proadm'] = is_proadm

        context['projects'] = []
        response_projects = requestAPI(request.user.username, "GET", 'projects')
        if (response_projects.status_code != 404):
            projects_data = response_projects.json()
            projects_participant = []
            projects_list = {}
            for curr_project in projects_data['projects']:
                if (is_sysadm):
                    projects_participant.append({'id': curr_project['project_id'], 'name': curr_project['name']})
                elif (request.user.user_id == curr_project['owner_id']):
                    projects_participant.append({'id': curr_project['project_id'], 'name': curr_project['name']})
                    permissions_list.append({ 'type': 'proown', 'type_id': curr_project['project_id']})
                else:
                    for curr_permission in permissions_list:
                        if (curr_permission['type'] == 'propar' or curr_permission['type'] == 'provie'):
                            if (curr_project['project_id'] == curr_permission['type_id']):
                                projects_list[curr_project['project_id']] = curr_project['name']
                        elif (curr_permission['type'] == 'catpar' or curr_permission['type'] == 'catvie'):
                            response_categories = requestAPI(request.user.username, "GET", 'categories/' + str(curr_permission['type_id']))
                            if (response_categories.status_code != 404 and
                                response_categories.json()['category']['project_id'] == curr_project['project_id']):
                                projects_list[curr_project['project_id']] = curr_project['name']
                        elif (curr_permission['type'] == 'annpar' or curr_permission['type'] == 'annvie'):
                            response_annotations = requestAPI(request.user.username, "GET", 'annotations/' + str(curr_permission['type_id']))
                            if (response_annotations.status_code != 404 and
                                response_annotations.json()['annotation']['project_id'] == curr_project['project_id']):
                                projects_list[curr_project['project_id']] = curr_project['name']

            for curr_project in projects_list:
                projects_participant.append({'id': curr_project, 'name': projects_list[curr_project]})
            context['projects'] = projects_participant

        request.session['permissions'] = permissions_list

    return render(request, 'memento/home.html', context)


@login_required
def manage_users(request):
    if (not checkPermissions(request.session['permissions'], 'sysadm', None, None, None, None)):
        return redirect('/memento')

    context = {}
    context['usernames'] = []
    response = requestAPI(request.user.username, "GET", 'users')
    if (response.status_code != 404):
        users_data = response.json()
        users_list =  []
        for curr_user in users_data['users']:
            users_list.append(curr_user['username'])
        context['usernames'] = users_list

    return render(request, 'memento/manage_users.html', context)


@login_required
def new_user(request):
    if (not checkPermissions(request.session['permissions'], 'sysadm', None, None, None, None)):
        return redirect('/memento')

    if request.method == 'GET':
        form = NewUserForm()
        context = {'form': form}
        return render(request, 'memento/new_user.html', context)
    if request.method == 'POST':
        form = NewUserForm(request.POST)
        if form.is_valid():
            username = form.cleaned_data.get('username')
            name = form.cleaned_data.get('name')
            email = form.cleaned_data.get('email')
            password = form.cleaned_data.get('password')

            response = requestAPI(request.user.username, "POST", 'users', payload={'username': username, 'name': name, 'email': email, 'password': password, 'settings': ''})

            next_actions = []
            if (response.status_code != 201):
                next_actions.append({ 'url': reverse(views.home), 'text': 'Go back to the main menu'})
                return return_message(request, 'Could not create user', [], 'nok', next_actions)
            else:
                next_actions.append({ 'url': reverse(views.home), 'text': 'Go back to the main menu'})
                next_actions.append({ 'url': reverse('edit_user') + '?username=' + username, 'text': 'Edit the new user'})
                return return_message(request, 'New user created', [], 'ok', next_actions)
        else:
            context = {'form': form}
            return render(request, 'memento/new_user.html', context)


@login_required
def edit_user(request):
    if (not checkPermissions(request.session['permissions'], 'sysadm', None, None, None, None)):
        return redirect('/memento')

    if request.method == 'GET':
        response = requestAPI(request.user.username, "GET", 'users/byusername/' + request.GET.get('username', None))
        if (response.status_code == 404):
            next_actions = []
            next_actions.append({ 'url': reverse(views.home), 'text': 'Go back to the main menu'})
            return return_message(request, 'User not found', [], 'nok', next_actions)

        users_data = response.json()
        user_id = users_data['user']['user_id']
        request.session['selected_user_id'] = int(user_id)
        form = NewUserForm(initial={'username': users_data['user']['username'],
                                    'name': users_data['user']['name'],
                                    'email': users_data['user']['email'],
                                    'usettings': users_data['user']['settings'],
                                    'password': '', 'password_r': ''})
        context = {'form': form}
        context['is_sysadm'] = 0
        context['is_proadm'] = 0
        context['is_sysadm_change'] = 1
        context['is_proadm_change'] = 1
        if (user_id == 1 or user_id == request.user.user_id):
            context['is_sysadm_change'] = 0
            context['is_proadm_change'] = 0

        response = requestAPI(request.user.username, "GET", 'permissions/byfilter/' + str(user_id) + '/none/0')
        permissions_list = []
        if (response.status_code != 404):
            permissions_data = response.json()
            for curr_permission in permissions_data['permissions']:
                permissions_list.append({ 'type': curr_permission['type'], 'type_id': curr_permission['type_id']})
                if curr_permission['type'] == 'sysadm':
                    context['is_sysadm'] = 1
                elif curr_permission['type'] == 'proadm':
                    context['is_proadm'] = 1

        context['projects_owned'] = 'None'
        context['projects_participant'] = 'None'
        context['projects_viewer'] = 'None'
        response = requestAPI(request.user.username, "GET", 'projects')
        if (response.status_code != 404):
            projects_data = response.json()
            projects_owned = []
            projects_participant = []
            projects_viewer = []
            projects_list_p = {}
            projects_list_v = {}
            for curr_project in projects_data['projects']:
                if (int(user_id) == curr_project['owner_id']):
                    projects_owned.append(curr_project['name'])
                else:
                    for curr_permission in permissions_list:
                        if (curr_permission['type'] == 'propar' or curr_permission['type'] == 'provie'):
                            if (curr_project['project_id'] == curr_permission['type_id']):
                                if (curr_permission['type'] == 'propar'):
                                    projects_list_p[curr_project['project_id']] = curr_project['name']
                                else:
                                    projects_list_v[curr_project['project_id']] = curr_project['name']
                        elif (curr_permission['type'] == 'catpar' or curr_permission['type'] == 'catvie'):
                            response_categories = requestAPI(request.user.username, "GET", 'categories/' + str(curr_permission['type_id']))
                            if (response_categories.status_code != 404 and
                                response_categories.json()['category']['project_id'] == curr_project['project_id']):
                                if (curr_permission['type'] == 'catpar'):
                                    projects_list_p[curr_project['project_id']] = curr_project['name']
                                else:
                                    projects_list_v[curr_project['project_id']] = curr_project['name']
                        elif (curr_permission['type'] == 'annpar' or curr_permission['type'] == 'annvie'):
                            response_annotations = requestAPI(request.user.username, "GET", 'annotations/' + str(curr_permission['type_id']))
                            if (response_annotations.status_code != 404 and
                                response_annotations.json()['annotation']['project_id'] == curr_project['project_id']):
                                if (curr_permission['type'] == 'annpar'):
                                    projects_list_p[curr_project['project_id']] = curr_project['name']
                                else:
                                    projects_list_v[curr_project['project_id']] = curr_project['name']

            for curr_project in projects_list_p:
                projects_participant.append(projects_list_p[curr_project])
            for curr_project in projects_list_v:
                projects_viewer.append(projects_list_v[curr_project])

            if (projects_owned):
                context['projects_owned'] = ', '.join(projects_owned)
            if (projects_participant):
                context['projects_participant'] = ', '.join(projects_participant)
            if (projects_viewer):
                context['projects_viewer'] = ', '.join(projects_viewer)

        return render(request, 'memento/edit_user.html', context)
    if request.method == 'POST':
        form = NewUserForm(request.POST)
        if form.is_valid():
            user_id = request.session['selected_user_id']
            username = form.cleaned_data.get('username')
            name = form.cleaned_data.get('name')
            email = form.cleaned_data.get('email')
            usettings = form.cleaned_data.get('usettings')
            if (not usettings):
                usettings = ''
            password = form.cleaned_data.get('password')
            response = requestAPI(request.user.username, "PUT", 'users/' + str(user_id), payload={'username': username, 'name': name, 'email': email, 'settings': usettings, 'password': password})
            next_actions = []
            if (response.status_code != 201):
                next_actions.append({ 'url': reverse(views.home), 'text': 'Go back to the main menu'})
                return return_message(request, 'Could not update user', [], 'nok', next_actions)
            else:
                next_actions.append({ 'url': reverse(views.home), 'text': 'Go back to the main menu'})
                next_actions.append({ 'url': reverse('edit_user') + '?username=' + username, 'text': 'Edit the user again'})
                return return_message(request, 'User updated', [], 'ok', next_actions)
        else:
            context = {'form': form}
            return render(request, 'memento/edit_user.html', context)


@login_required
def update_permission(request):
    if (not checkPermissions(request.session['permissions'], 'sysadm', None, None, None, None)):
        return redirect('/memento')

    user_id = request.session['selected_user_id']
    username = request.GET.get('username', None)
    permission_type = request.GET.get('type', None)
    permission_type_id = int(request.GET.get('type_id', None))

    response = requestAPI(request.user.username, "DELETE", 'permissions/byfilter/' + str(user_id) + '/' + permission_type + '/0')
    if (user_id == 1):
        return redirect('/memento')
    if (permission_type_id == 1):
        requestAPI(request.user.username, "POST", 'permissions', payload={'user_id': user_id, 'type': permission_type, 'type_id': permission_type_id})

    return redirect('memento/edit_user?username=' + username)


@login_required
def change_password(request):
    if request.method == 'GET':
        form = ChangePasswordForm(initial={'usettings': request.user.settings,
                                        'password': '', 'password_r': ''})
        context = {'form': form}
        return render(request, 'memento/change_password.html', context)
    if request.method == 'POST':
        form = ChangePasswordForm(request.POST)
        if form.is_valid():
            user_id = request.user.user_id
            username = request.user.username
            name = request.user.name
            email = request.user.email
            usettings = form.cleaned_data.get('usettings')
            if (not usettings):
                usettings = ''
            password = form.cleaned_data.get('password')
            response = requestAPI(request.user.username, "POST", 'users/' + str(user_id), payload={'username': username, 'name': name, 'email': email, 'settings': usettings, 'password': password})

            next_actions = []
            if (response.status_code != 201):
                next_actions.append({ 'url': reverse(views.home), 'text': 'Go back to the main menu'})
                return return_message(request, 'Could not update user', [], 'nok', next_actions)
            else:
                next_actions.append({ 'url': reverse(views.home), 'text': 'Go back to the main menu'})
                return return_message(request, 'User updated', [], 'ok', next_actions)
        else:
            context = {'form': form}
            return render(request, 'memento/change_password.html', context)


@login_required
def delete_user(request):
    if (not checkPermissions(request.session['permissions'], 'sysadm', None, None, None, None)):
        return redirect('/memento')

    user_id = request.session['selected_user_id']
    if (user_id == 1 or user_id == request.user.user_id):
        return redirect('/memento')

    response = requestAPI(request.user.username, "DELETE", 'users/' + str(user_id))
    response = requestAPI(request.user.username, "DELETE", 'permissions/byfilter/' + str(user_id) + '/none/0')

    response = requestAPI(request.user.username, "PUT", 'utilities/change_ownership/' + str(user_id) + '/' + str(request.user.user_id), payload={})

    next_actions = []
    next_actions.append({ 'url': reverse(views.home), 'text': 'Go back to the main menu'})
    return return_message(request, 'User removed', [], 'ok', next_actions)


@login_required
def manage_projects(request):
    is_sysadm = checkPermissions(request.session['permissions'], 'sysadm', None, None, None, None)
    is_proadm = checkPermissions(request.session['permissions'], 'proadm', None, None, None, None)
    if (not is_sysadm and not is_proadm):
        return redirect('/memento')

    context = {}
    context['projects'] = []
    response = requestAPI(request.user.username, "GET", 'projects')
    if (response.status_code != 404):
        projects_data = response.json()
        projects_list =  []
        for curr_project in projects_data['projects']:
            if (is_sysadm or (is_proadm and request.user.user_id == curr_project['owner_id'])):
                projects_list.append({'id': curr_project['project_id'], 'name': curr_project['name']})
        context['projects'] = projects_list

    return render(request, 'memento/manage_projects.html', context)


@login_required
def ft_share_image(request):
    if (not checkPermissions(request.session['permissions'], 'proadm', None, None, None, None)):
        return redirect('/memento')

    if request.method == 'GET':
        form = NewFTShareImageForm()
        context = {'form': form}
        context['formats'] = [{'id': 1, 'description': 'Fast'}, {'id': 2, 'description': 'Fast with transparency'}, {'id': 4, 'description': 'Tiled image'}, {'id': 5, 'description': 'Tiled image with transparency'}, {'id': 3, 'description': 'Maximum quality'}]
        return render(request, 'memento/ft_share_image.html', context)
    if request.method == 'POST':
        form = NewFTShareImageForm(request.POST, request.FILES)
        name = form.data['name']
        format = form.data['format']
        uri = form.data['url']

        if ((not uri or uri == '') and '/' in request.FILES['file'].name):
            next_actions = []
            next_actions.append({ 'url': reverse(views.home), 'text': 'Go back to the main menu'})
            return return_message_content(request, 'Could not create image', [], 'nok', next_actions)

        response = requestAPI(request.user.username, "POST", 'projects', payload={'name': name, 'owner_id': request.user.user_id, 'settings': ''})
        if (response.status_code != 201):
            next_actions = []
            next_actions.append({ 'url': reverse(views.home), 'text': 'Go back to the main menu'})
            return return_message_content(request, 'Could not create project', [], 'nok', next_actions)
        else:
            project_id = response.json()['project']['project_id']
            response = requestAPI(request.user.username, "POST", 'categories',
                                  payload={'name': 'default', 'settings': '' , 'project_id': project_id, 'owner_id': request.user.user_id})
            category_id = response.json()['category']['category_id']

            response = None
            if (uri and uri != ''):
                response = requestAPI(request.user.username, "POST", 'images',
                                      payload={'filepath' : '', 'format' : 0, 'name': 'image', 'uri': uri, 'type': 'E', 'resolution': '', 'project_id': project_id, 'owner_id': request.user.user_id})
            else:
                filepath = settings.IMAGES_ROOT + '/' + request.FILES['file'].name.replace(' ', '_')
                with open(filepath, 'wb+') as destination:
                    for chunk in request.FILES['file'].chunks():
                        destination.write(chunk)
                uri = 'temp'
                type = ''
                if (format == 5 or format == '5' or format == 4 or format == '4'):
                    type = 'T'
                response = requestAPI(request.user.username, "POST", 'images',
                                      payload={'filepath' : filepath, 'format' : format, 'name': 'image', 'uri': uri, 'type': type, 'project_id': project_id, 'owner_id': request.user.user_id})
                os.remove(filepath)

            image_data = response.json()['image']
            image_id = image_data['image_id']

            shared = get_random_string(50)

            response = requestAPI(request.user.username, "POST", 'annotations',
                                  payload={'name': 'image', 'status' : 'N', 'shared' : shared, 'image_id': image_id,
                                             'project_id': project_id, 'category_id': category_id, 'owner_id': request.user.user_id})
            annotation_id = response.json()['annotation']['annotation_id']

            response = requestAPI(request.user.username, "POST", 'layers',
                                  payload={'name': 'base', 'data': '', 'image_id': image_id, 'sequence': 1, 'parent_id': 0, 'annotation_id': annotation_id, 'owner_id': request.user.user_id})

            submessages = []
            submessages.append('Send this URL to the person/s you want to grant anonymous access to this annotation')
            submessages.append(request.build_absolute_uri('viewer') + '?project_id=' + str(project_id) + '&category_id=' + str(category_id) +
                                                                               '&annotation_id=' + str(annotation_id) + '&share=' + shared)
            next_actions = []
            next_actions.append({ 'url': reverse(views.home), 'text': 'Go back to the main menu'})
            next_actions.append({ 'url': reverse('edit_project') + '?project_id=' + str(project_id),
                                  'text': 'Customize the new project'})
            return return_message_content(request, 'New image shared', submessages, 'ok', next_actions)


@login_required
def new_project(request):
    if (not checkPermissions(request.session['permissions'], 'proadm', None, None, None, None)):
        return redirect('/memento')

    if request.method == 'GET':
        form = NewProjectForm()
        context = {'form': form}
        return render(request, 'memento/new_project.html', context)
    if request.method == 'POST':
        form = NewProjectForm(request.POST)
        if form.is_valid():
            name = form.cleaned_data.get('name')

            response = requestAPI(request.user.username, "POST", 'projects',
                                  payload={'name': name, 'owner_id': request.user.user_id, 'settings': ''})
            next_actions = []
            if (response.status_code != 201):
                next_actions.append({ 'url': reverse(views.home), 'text': 'Go back to the main menu'})
                return return_message(request, 'Could not create project', [], 'nok', next_actions)
            else:
                project_id = response.json()['project']['project_id']
                response = requestAPI(request.user.username, "POST", 'categories',
                                      payload={'name': 'default', 'settings': '', 'project_id': response.json()['project']['project_id'], 'owner_id': request.user.user_id})
                next_actions.append({ 'url': reverse(views.home), 'text': 'Go back to the main menu'})
                next_actions.append({ 'url': reverse('edit_project') + '?project_id=' + str(project_id),
                                      'text': 'Edit the new project'})
                return return_message(request, 'New project created', [], 'ok', next_actions)
        else:
            context = {'form': form}
            return render(request, 'memento/new_project.html', context)


@login_required
def edit_project(request):
    if request.method == 'GET':
        project_id = int(request.GET.get('project_id', None))
        response = requestAPI(request.user.username, "GET", 'projects/' + str(project_id))
        if (response.status_code == 404):
            next_actions = []
            next_actions.append({ 'url': reverse(views.home), 'text': 'Go back to the main menu'})
            return return_message(request, 'Project not found', [], 'nok', next_actions)

        project_data = response.json()
        owner_id = project_data['project']['owner_id']
        if (not checkPermissions(request.session['permissions'], 'sysadm', None, None, None, None) and
           (not checkPermissions(request.session['permissions'], 'proadm', None, None, None, None) or owner_id != request.user.user_id)):
            return redirect('/memento')

        request.session['selected_project_id'] = int(project_id)
        request.session['selected_project_owner'] = int(owner_id)

        form = NewProjectForm(initial={'name': project_data['project']['name'], 'psettings': project_data['project']['settings']})
        context = {'form': form}

        context['owner'] = ''
        if (owner_id == request.user.user_id):
            context['owner'] = request.user.username
        else:
            response = requestAPI(request.user.username, "GET", 'users/' + str(owner_id))
            if (response.status_code != 404):
                context['owner'] = response.json()['user']['username']
        context['maxlengthlist'] = settings.MAXLENGTHLIST
        if ('maxlengthlist' in request.session['settings']):
            context['maxlengthlist'] = request.session['settings']['maxlengthlist']

        context['participants'] = []
        response = requestAPI(request.user.username, "GET", 'permissions/byfilter/0/propar/' + str(project_id))
        if (response.status_code != 404):
            permissions_data = response.json()
            participants = []
            for curr_permission in permissions_data['permissions']:
                response_user = requestAPI(request.user.username, "GET", 'users/' + str(curr_permission['user_id']))
                if (response_user.status_code != 404):
                    user_data = response_user.json()
                    participants.append({'id': user_data['user']['user_id'], 'username': user_data['user']['username']})

                context['participants'] = participants

        context['viewers'] = []
        response = requestAPI(request.user.username, "GET", 'permissions/byfilter/0/provie/' + str(project_id))
        if (response.status_code != 404):
            permissions_data = response.json()
            viewers = []
            for curr_permission in permissions_data['permissions']:
                response_user = requestAPI(request.user.username, "GET", 'users/' + str(curr_permission['user_id']))
                if (response_user.status_code != 404):
                    user_data = response_user.json()
                    viewers.append({'id': user_data['user']['user_id'], 'username': user_data['user']['username']})

                context['viewers'] = viewers

        context['labels'] = {}
        response = requestAPI(request.user.username, "GET", 'labels/byproject_id/' + str(project_id))
        if (response.status_code != 404):
            labels_data = response.json()
            labels = []
            for curr_label in labels_data['labels']:
                labels.append({'id': curr_label['label_id'], 'name': curr_label['name']})

                context['labels'] = labels

        context['categories'] = []
        response = requestAPI(request.user.username, "GET", 'categories/byproject_id/' + str(project_id))
        if (response.status_code != 404):
            categories_data = response.json()
            categories = []
            for curr_category in categories_data['categories']:
                categories.append({'id': curr_category['category_id'], 'name': curr_category['name']})

                context['categories'] = categories

        context['classifications'] = []
        response = requestAPI(request.user.username, "GET", 'classifications/byproject_id/' + str(project_id))
        if (response.status_code != 404):
            classifications_data = response.json()
            classifications = []
            for curr_classification in classifications_data['classifications']:
                classifications.append({'id': curr_classification['classification_id'], 'name': curr_classification['name']})

                context['classifications'] = classifications

        context['images'] = []
        response = requestAPI(request.user.username, "GET", 'images/byproject_id/' + str(project_id))
        if (response.status_code != 404):
            images_data = response.json()
            images = []
            for curr_image in images_data['images']:
                images.append({'id': curr_image['image_id'], 'name': curr_image['name']})

                context['images'] = images

        response = requestAPI(request.user.username, "GET", 'utilities/project_summary/' + str(project_id))
        project_data = response.json()
        context['total_participants'] = project_data['total_participants']
        context['total_annotations'] = project_data['total_annotations']
        context['total_annotations_submitted'] = project_data['total_annotations_submitted']
        context['total_annotations_shared'] = project_data['total_annotations_shared']

        return render(request, 'memento/edit_project.html', context)
    if request.method == 'POST':
        project_id = request.session['selected_project_id']
        owner_id = request.session['selected_project_owner']
        if (not checkPermissions(request.session['permissions'], 'sysadm', None, None, None, None) and
           (not checkPermissions(request.session['permissions'], 'proadm', None, None, None, None) or owner_id != request.user.user_id)):
            return redirect('/memento')

        form = NewProjectForm(request.POST)
        if form.is_valid():
            name = form.cleaned_data.get('name')
            psettings = form.cleaned_data.get('psettings')
            if (not psettings):
                psettings = ''
            response = requestAPI(request.user.username, "GET", 'projects/' + str(project_id))
            if (response.status_code == 404):
                next_actions = []
                next_actions.append({ 'url': reverse(views.home), 'text': 'Go back to the main menu'})
                return return_message(request, 'Project not found', [], 'nok', next_actions)

            project_data = response.json()
            response = requestAPI(request.user.username, "PUT", 'projects/' + str(project_id), payload={'name': name, 'settings': psettings, 'owner_id': project_data['project']['owner_id']})
            next_actions = []
            if (response.status_code != 201):
                next_actions.append({ 'url': reverse(views.home), 'text': 'Go back to the main menu'})
                return return_message(request, 'Could not update project', [], 'nok', next_actions)
            else:
                next_actions.append({ 'url': reverse(views.home), 'text': 'Go back to the main menu'})
                next_actions.append({ 'url': reverse('edit_project') + '?project_id=' + str(response.json()['project']['project_id']),
                                      'text': 'Edit the project again'})
                return return_message(request, 'Project updated', [], 'ok', next_actions)
        else:
            context = {'form': form}
            return render(request, 'memento/edit_project.html', context)


@login_required
def delete_project(request):
    project_id = request.session['selected_project_id']
    owner_id = request.session['selected_project_owner']
    if (not checkPermissions(request.session['permissions'], 'sysadm', None, None, None, None) and
       (not checkPermissions(request.session['permissions'], 'proadm', None, None, None, None) or owner_id != request.user.user_id)):
        return redirect('/memento')

    response = requestAPI(request.user.username, "DELETE", 'projects/' + str(project_id))
    response = requestAPI(request.user.username, "DELETE", 'permissions/byfilter/0/propar/' + str(project_id))
    response = requestAPI(request.user.username, "DELETE", 'permissions/byfilter/0/provie/' + str(project_id))

    response = requestAPI(request.user.username, "GET", 'categories/byproject_id/' + str(project_id))
    if (response.status_code != 404):
        categories_data = response.json()
        for curr_category in categories_data['categories']:
            response = requestAPI(request.user.username, "DELETE", 'categories/' + str(curr_category['category_id']))
            response = requestAPI(request.user.username, "DELETE", 'permissions/byfilter/0/catpar/' + str(curr_category['category_id']))
            response = requestAPI(request.user.username, "DELETE", 'permissions/byfilter/0/catvie/' + str(curr_category['category_id']))

    response = requestAPI(request.user.username, "GET", 'classifications/byproject_id/' + str(project_id))
    if (response.status_code != 404):
        classifications_data = response.json()
        for curr_classification in classifications_data['classifications']:
            response = requestAPI(request.user.username, "DELETE", 'classifications/' + str(curr_classification['classification_id']))
            response = requestAPI(request.user.username, "DELETE", 'categories_classifications/byfilter/0/' + str(curr_classification['classification_id']))

    response = requestAPI(request.user.username, "GET", 'images/byproject_id/' + str(project_id))
    if (response.status_code != 404):
        images_data = response.json()
        for curr_image in images_data['images']:
            response = requestAPI(request.user.username, "DELETE", 'images/' + str(curr_image['image_id']))

    response = requestAPI(request.user.username, "GET", 'labels/byproject_id/' + str(project_id))
    if (response.status_code != 404):
        labels_data = response.json()
        for curr_label in labels_data['labels']:
            response = requestAPI(request.user.username, "DELETE", 'labels/' + str(curr_label['label_id']))
            response = requestAPI(request.user.username, "DELETE", 'annotations_labels/byfilter/0/' + str(curr_label['label_id']))

    response = requestAPI(request.user.username, "GET", 'annotations/byproject_id/' + str(project_id))
    if (response.status_code != 404):
        annotations_data = response.json()
        for curr_annotation in annotations_data['annotations']:
            response = requestAPI(request.user.username, "DELETE", 'annotations/' + str(curr_annotation['annotation_id']))
            response = requestAPI(request.user.username, "DELETE", 'permissions/byfilter/0/annpar/' + str(curr_annotation['annotation_id']))
            response = requestAPI(request.user.username, "DELETE", 'permissions/byfilter/0/annvie/' + str(curr_annotation['annotation_id']))
            response = requestAPI(request.user.username, "DELETE", 'annotations_labels/byfilter/' + str(curr_annotation['annotation_id']) + '/0')

            response = requestAPI(request.user.username, "GET", 'layers/byannotation_id/' + str(curr_annotation['annotation_id']))
            if (response.status_code != 404):
                layers_data = response.json()
                for curr_layer in layers_data['layers']:
                    response = requestAPI(request.user.username, "DELETE", 'layers/' + str(curr_layer['layer_id']))
                    response = requestAPI(request.user.username, "GET", 'comments/bylayer_id/' + str(curr_layer['layer_id']))
                    if (response.status_code != 404):
                        comments_data = response.json()
                        for curr_comment in comments_data['comments']:
                            response = requestAPI(request.user.username, "DELETE", 'comments/' + str(curr_comment['comment_id']))

    next_actions = []
    next_actions.append({ 'url': reverse(views.home), 'text': 'Go back to the main menu'})
    return return_message(request, 'Project removed', [], 'ok', next_actions)


@login_required
def export_data(request):
    project_id = request.session['selected_project_id']
    owner_id = request.session['selected_project_owner']
    if (not checkPermissions(request.session['permissions'], 'sysadm', None, None, None, None) and
       (not checkPermissions(request.session['permissions'], 'proadm', None, None, None, None) or owner_id != request.user.user_id)):
        return redirect('/memento')

    formattype = request.GET.get('formattype', '')

    response = requestAPI(request.user.username, "GET", 'projects/' + str(project_id))
    if (response.status_code == 404):
        next_actions = []
        next_actions.append({ 'url': reverse(views.home), 'text': 'Go back to the main menu'})
        return return_message(request, 'Project not found', [], 'nok', next_actions)
    project_name = response.json()['project']['name']

    response = requestAPI(request.user.username, "GET", 'labels/byproject_id/' + str(project_id))
    if (response.status_code == 404):
        next_actions = []
        next_actions.append({ 'url': reverse(views.home), 'text': 'Go back to the main menu'})
        return return_message(request, 'The project has no data', [], 'nok', next_actions)

    labels_data = response.json()['labels']

    response = requestAPI(request.user.username, "GET", 'utilities/project_data/' + str(project_id))
    if (response.status_code == 404):
        next_actions = []
        next_actions.append({ 'url': reverse(views.home), 'text': 'Go back to the main menu'})
        return return_message(request, 'The project has no data', [], 'nok', next_actions)

    project_data = response.json()['project_data']

    last_cat = ''
    last_cla = ''
    last_ann = ''
    last_img = ''
    last_sta = ''
    last_lab = {}
    for label in labels_data:
        last_lab[label['name']] = 'N'

    if (formattype == 'csv'):
        file_data = 'category,classification,annotation,image,uri,submitted,'
        for label in labels_data:
            file_data = file_data + label['name'] + ','

        file_data = file_data[:-1]
        file_data = file_data + '\n'
        for curr_data_row in project_data:
            curr_cat = curr_data_row['c2']
            curr_cla = 'No classification'
            if (curr_data_row['c3']):
                curr_cla = curr_data_row['c3']
            curr_ann = curr_data_row['c4']
            curr_img = curr_data_row['c5']
            curr_uri = curr_data_row['c8']
            curr_sta = curr_data_row['c6']

            if (last_cat == ''):
                last_cat = curr_cat
                last_cla = curr_cla
                last_ann = curr_ann
                last_img = curr_img
                last_uri = curr_uri
                last_sta = curr_sta

            if (curr_cat == last_cat and curr_cla == last_cla and curr_ann == last_ann and curr_img == last_img):
                if (curr_data_row['c7']):
                    last_lab[curr_data_row['c7']] = 'Y'
            else:
                new_line = ''
                new_line = new_line + last_cat + ','
                new_line = new_line + last_cla + ','
                new_line = new_line + last_ann + ','
                new_line = new_line + last_img + ','
                new_line = new_line + last_uri + ','
                new_line = new_line + last_sta + ','
                for curr_lab in last_lab:
                    new_line = new_line + last_lab[curr_lab] + ','
                    last_lab[curr_lab] = 'N'
                last_cat = curr_cat
                last_cla = curr_cla
                last_ann = curr_ann
                last_img = curr_img
                last_uri = curr_uri
                last_sta = curr_sta
                if (curr_data_row['c7']):
                    last_lab[curr_data_row['c7']] = 'Y'

                new_line = new_line[:-1]
                file_data = file_data + new_line + '\n'

        new_line = ''
        new_line = new_line + last_cat + ','
        new_line = new_line + last_cla + ','
        new_line = new_line + last_ann + ','
        new_line = new_line + last_img + ','
        new_line = new_line + last_uri + ','
        new_line = new_line + last_sta + ','
        for curr_lab in last_lab:
            new_line = new_line + last_lab[curr_lab] + ','

        new_line = new_line[:-1]
        file_data = file_data + new_line + '\n'

        response = HttpResponse(file_data, content_type='text/csv charset=utf-8')
        response['Content-Disposition'] = 'attachment; filename="' + project_name + '_data.csv"'
        return response
    elif (formattype == 'json'):
        file_data = { "categories": {} }

        for curr_data_row in project_data:
            curr_cat = curr_data_row['c2']
            curr_cla = 'No classification'
            if (curr_data_row['c3'] and curr_data_row['c3'] != 'NULL'):
                curr_cla = curr_data_row['c3']
            curr_ann = curr_data_row['c4']
            curr_img = curr_data_row['c5']
            curr_uri = curr_data_row['c8']
            curr_sta = curr_data_row['c6']

            if (last_cat == ''):
                last_cat = curr_cat
                last_cla = curr_cla
                last_ann = curr_ann
                last_img = curr_img
                last_uri = curr_uri
                last_sta = curr_sta

            if (curr_cat == last_cat and curr_cla == last_cla and curr_ann == last_ann and curr_img == last_img):
                if (curr_data_row['c7']):
                    last_lab[curr_data_row['c7']] = 'Y'
            else:
                if (not last_cat in file_data["categories"]):
                    file_data["categories"][last_cat] = { 'classification': last_cla, 'annotations': {} }
                if (not last_ann in file_data["categories"][last_cat]["annotations"]):
                    file_data["categories"][last_cat]["annotations"][last_ann] = {}
                file_data["categories"][last_cat]["annotations"][last_ann] = {}
                file_data["categories"][last_cat]["annotations"][last_ann]["image"] = last_img
                file_data["categories"][last_cat]["annotations"][last_ann]["status"] = last_sta
                file_data["categories"][last_cat]["annotations"][last_ann]["labels"] = {}
                for curr_lab in last_lab:
                    file_data["categories"][last_cat]["annotations"][last_ann]["labels"][curr_lab] = last_lab[curr_lab]
                    last_lab[curr_lab] = 'N'
                last_cat = curr_cat
                last_cla = curr_cla
                last_ann = curr_ann
                last_img = curr_img
                last_uri = curr_uri
                last_sta = curr_sta
                if (curr_data_row['c7']):
                    last_lab[curr_data_row['c7']] = 'Y'

        if (not last_cat in file_data["categories"]):
            file_data["categories"][last_cat] = { 'classification': last_cla, 'annotations': {} }
        if (not last_ann in file_data["categories"][last_cat]["annotations"]):
            file_data["categories"][last_cat]["annotations"][last_ann] = {}
        file_data["categories"][last_cat]["annotations"][last_ann] = {}
        file_data["categories"][last_cat]["annotations"][last_ann]["image"] = last_img
        file_data["categories"][last_cat]["annotations"][last_ann]["uri"] = last_uri
        file_data["categories"][last_cat]["annotations"][last_ann]["status"] = last_sta
        file_data["categories"][last_cat]["annotations"][last_ann]["labels"] = {}
        for curr_lab in last_lab:
            file_data["categories"][last_cat]["annotations"][last_ann]["labels"][curr_lab] = last_lab[curr_lab]

        response = HttpResponse(json.dumps(file_data, indent = 4), content_type='application/json charset=utf-8')
        response['Content-Disposition'] = 'attachment; filename="' + project_name + '_data.json"'
        return response

    return HttpResponse(status=404)


@login_required
def export_comments(request):
    project_id = request.session['selected_project_id']
    owner_id = request.session['selected_project_owner']
    if (not checkPermissions(request.session['permissions'], 'sysadm', None, None, None, None) and
       (not checkPermissions(request.session['permissions'], 'proadm', None, None, None, None) or owner_id != request.user.user_id)):
        return redirect('/memento')

    formattype = request.GET.get('formattype', '')

    response = requestAPI(request.user.username, "GET", 'projects/' + str(project_id))
    if (response.status_code == 404):
        next_actions = []
        next_actions.append({ 'url': reverse(views.home), 'text': 'Go back to the main menu'})
        return return_message(request, 'Project not found', [], 'nok', next_actions)
    project_name = response.json()['project']['name']

    response = requestAPI(request.user.username, "GET", 'utilities/project_comments/' + str(project_id))
    if (response.status_code == 404):
        next_actions = []
        next_actions.append({ 'url': reverse(views.home), 'text': 'Go back to the main menu'})
        return return_message(request, 'The project has no comments', [], 'nok', next_actions)

    project_comments = response.json()['project_comments']

    file_data = {}
    for curr_comment_row in project_comments:
        curr_cat = curr_comment_row['c2']
        curr_ann = curr_comment_row['c3']
        curr_lay = curr_comment_row['c4']
        curr_com = curr_comment_row['c5']
        if (not curr_cat in file_data):
            file_data[curr_cat] = {}
        if (not curr_ann in file_data[curr_cat]):
            file_data[curr_cat][curr_ann] = {}
        if (not curr_lay in file_data[curr_cat][curr_ann]):
            file_data[curr_cat][curr_ann][curr_lay] = []
        file_data[curr_cat][curr_ann][curr_lay].append(curr_com)

    response = HttpResponse(json.dumps(file_data, indent = 4), content_type='application/json charset=utf-8')
    response['Content-Disposition'] = 'attachment; filename="' + project_name + '_comments.json"'
    return response


@login_required
def export_rois(request):
    project_id = request.session['selected_project_id']
    owner_id = request.session['selected_project_owner']
    if (not checkPermissions(request.session['permissions'], 'sysadm', None, None, None, None) and
       (not checkPermissions(request.session['permissions'], 'proadm', None, None, None, None) or owner_id != request.user.user_id)):
        return redirect('/memento')

    formattype = request.GET.get('formattype', '')

    response = requestAPI(request.user.username, "GET", 'projects/' + str(project_id))
    if (response.status_code == 404):
        next_actions = []
        next_actions.append({ 'url': reverse(views.home), 'text': 'Go back to the main menu'})
        return return_message(request, 'Project not found', [], 'nok', next_actions)
    project_name = response.json()['project']['name']

    response = requestAPI(request.user.username, "GET", 'utilities/project_rois/' + str(project_id))
    if (response.status_code == 404):
        next_actions = []
        next_actions.append({ 'url': reverse(views.home), 'text': 'Go back to the main menu'})
        return return_message(request, 'The project has no ROIs', [], 'nok', next_actions)

    project_rois = response.json()['project_rois']

    file_data = {}
    for curr_roi_row in project_rois:
        curr_cat = curr_roi_row['c2']
        curr_ann = curr_roi_row['c3']
        curr_lay = curr_roi_row['c4']
        curr_roi = curr_roi_row['c5']
        if (not curr_cat in file_data):
            file_data[curr_cat] = {}
        if (not curr_ann in file_data[curr_cat]):
            file_data[curr_cat][curr_ann] = {}
        if (not curr_lay in file_data[curr_cat][curr_ann]):
            file_data[curr_cat][curr_ann][curr_lay] = []
        file_data[curr_cat][curr_ann][curr_lay].append(curr_roi)

    response = HttpResponse(json.dumps(file_data, indent = 4), content_type='application/json charset=utf-8')
    response['Content-Disposition'] = 'attachment; filename="' + project_name + '_comments.json"'
    return response


@login_required
def new_participant(request):
    project_id = request.session['selected_project_id']
    owner_id = request.session['selected_project_owner']
    if (not checkPermissions(request.session['permissions'], 'sysadm', None, None, None, None) and
       (not checkPermissions(request.session['permissions'], 'proadm', None, None, None, None) or owner_id != request.user.user_id)):
        return redirect('/memento')

    if request.method == 'GET':
        request.session['selected_project_participant_category_id'] = None
        request.session['selected_project_participant_annotation_id'] = None
        category_id = request.GET.get('category_id', None)
        if (category_id):
            request.session['selected_project_participant_category_id'] = int(category_id)
        annotation_id = request.GET.get('annotation_id', None)
        if (annotation_id):
            request.session['selected_project_participant_annotation_id'] = int(annotation_id)
        response = requestAPI(request.user.username, "GET", 'projects/' + str(project_id))
        if (response.status_code == 404):
            next_actions = []
            next_actions.append({ 'url': reverse(views.home), 'text': 'Go back to the main menu'})
            return return_message(request, 'Project not found', [], 'nok', next_actions)

        form = NewParticipantForm()
        context = {'form': form}

        context['usernames'] = []
        response = requestAPI(request.user.username, "GET", 'users')
        if (response.status_code == 404):
            next_actions = []
            next_actions.append({ 'url': reverse(views.home), 'text': 'Go back to the main menu'})
            if (annotation_id):
                next_actions.append({ 'url': reverse('edit_annotation') +
                                            '?annotation_id=' + str(annotation_id),
                                      'text': 'Keep editing the annotation'})
            if (category_id):
                next_actions.append({ 'url': reverse('edit_category') +
                                            '?category_id=' + str(category_id),
                                      'text': 'Keep editing the category'})
            next_actions.append({ 'url': reverse('edit_project') +
                                         '?project_id=' + str(project_id),
                                  'text': 'Keep editing the project'})
            return return_message(request, 'No user candidates available to participate', [], 'nok', next_actions)

        users_data = response.json()
        users_list =  []
        for curr_user in users_data['users']:
            if (curr_user['user_id'] != owner_id):
                candidate = True
                response_permissions = requestAPI(request.user.username, "GET", 'permissions/byfilter/' + str(curr_user['user_id']) + '/none/0')
                if (response.status_code != 404):
                    permissions_data = response_permissions.json()['permissions']
                    for curr_permission in permissions_data:
                        if (curr_permission['type'] == 'propar' and curr_permission['type_id'] == project_id or
                            curr_permission['type'] == 'catpar' and curr_permission['type_id'] == category_id or
                            curr_permission['type'] == 'annpar' and curr_permission['type_id'] == annotation_id):
                            candidate = False
                            break
                if (candidate):
                    users_list.append({'id' : curr_user['user_id'], 'username': curr_user['username']})

            context['usernames'] = users_list
        return render(request, 'memento/new_participant.html', context)
    if request.method == 'POST':
        form = NewParticipantForm(request.POST)
        user_id = form.data['user_id']

        response = requestAPI(request.user.username, "GET", 'users/' + str(user_id))
        if (response.status_code == 404):
            next_actions = []
            next_actions.append({ 'url': reverse(views.home), 'text': 'Go back to the main menu'})
            return return_message(request, 'Participant not found', [], 'nok', next_actions)

        username = response.json()['user']['username']
        category_id = request.session['selected_project_participant_category_id']
        annotation_id = request.session['selected_project_participant_annotation_id']
        stype = 'propar'
        type_id = project_id
        if (annotation_id):
            stype = 'annpar'
            type_id = annotation_id
        elif (category_id):
            stype = 'catpar'
            type_id = category_id

        response = requestAPI(request.user.username, "POST", 'permissions', payload={'user_id': user_id, 'type': stype, 'type_id': type_id})
        next_actions = []
        if (response.status_code != 201):
            next_actions.append({ 'url': reverse(views.home), 'text': 'Go back to the main menu'})
            return return_message(request, 'Could not add participant', [], 'nok', next_actions)
        else:
            next_actions.append({ 'url': reverse(views.home), 'text': 'Go back to the main menu'})
            next_actions.append({ 'url': reverse('edit_participant') +
                                         '?username=' + username,
                                  'text': 'Edit the new participant'})
            if (annotation_id):
                next_actions.append({ 'url': reverse('edit_annotation') +
                                             '?annotation_id=' + str(annotation_id),
                                      'text': 'Keep editing the annotation'})
                next_actions.append({ 'url': reverse('edit_project') +
                                             '?project_id=' + str(project_id),
                                      'text': 'Keep editing the project'})
            if (category_id):
                next_actions.append({ 'url': reverse('edit_category') +
                                             '?category_id=' + str(category_id),
                                      'text': 'Keep editing the category'})
            next_actions.append({ 'url': reverse('edit_project') +
                                         '?project_id=' + str(project_id),
                                  'text': 'Keep editing the project'})
            return return_message(request, 'New participant added', [], 'ok', next_actions)


@login_required
def edit_participant(request):
    project_id = request.session['selected_project_id']
    owner_id = request.session['selected_project_owner']
    if (not checkPermissions(request.session['permissions'], 'sysadm', None, None, None, None) and
       (not checkPermissions(request.session['permissions'], 'proadm', None, None, None, None) or owner_id != request.user.user_id)):
        return redirect('/memento')

    if request.method == 'GET':
        request.session['selected_project_participant_category_id'] = None
        request.session['selected_project_participant_annotation_id'] = None
        category_id = request.GET.get('category_id', None)
        if (category_id):
            request.session['selected_project_participant_category_id'] = int(category_id)
        annotation_id = request.GET.get('annotation_id', None)
        if (annotation_id):
            request.session['selected_project_participant_annotation_id'] = int(annotation_id)
        username = request.GET.get('username', None)
        response = requestAPI(request.user.username, "GET", 'projects/' + str(project_id))
        if (response.status_code == 404):
            next_actions = []
            next_actions.append({ 'url': reverse(views.home), 'text': 'Go back to the main menu'})
            return return_message(request, 'Project not found', [], 'nok', next_actions)

        response = requestAPI(username, "GET", 'users/byusername/' + username)
        if (response.status_code == 404):
            next_actions = []
            next_actions.append({ 'url': reverse(views.home), 'text': 'Go back to the main menu'})
            return return_message(request, 'Participant not found', [], 'nok', next_actions)
        user_data = response.json()
        user_id = user_data['user']['user_id']
        request.session['selected_project_participant_id'] = int(user_id)

        context = {'username' : username}
        return render(request, 'memento/edit_participant.html', context)


def delete_participant(request):
    project_id = request.session['selected_project_id']
    owner_id = request.session['selected_project_owner']
    if (not checkPermissions(request.session['permissions'], 'sysadm', None, None, None, None) and
       (not checkPermissions(request.session['permissions'], 'proadm', None, None, None, None) or owner_id != request.user.user_id)):
        return redirect('/memento')

    user_id = request.session['selected_project_participant_id']
    category_id = request.session['selected_project_participant_category_id']
    annotation_id = request.session['selected_project_participant_annotation_id']
    stype = 'propar'
    type_id = project_id
    if (annotation_id):
        stype = 'annpar'
        type_id = annotation_id
    elif (category_id):
        stype = 'catpar'
        type_id = category_id

    response = requestAPI(request.user.username, "DELETE", 'permissions/' + str(user_id) + '/' + stype +'/' + str(type_id))

    next_actions = []
    next_actions.append({ 'url': reverse(views.home), 'text': 'Go back to the main menu'})
    if (annotation_id):
        next_actions.append({ 'url': reverse('edit_annotation') +
                                     '?annotation_id=' + str(annotation_id),
                              'text': 'Keep editing the annotation'})
        next_actions.append({ 'url': reverse('edit_project') +
                                     '?project_id=' + str(project_id),
                              'text': 'Keep editing the project'})
    if (category_id):
        next_actions.append({ 'url': reverse('edit_category') +
                                     '?category_id=' + str(category_id),
                              'text': 'Keep editing the category'})
    next_actions.append({ 'url': reverse('edit_project') +
                                '?project_id=' + str(project_id),
                          'text': 'Keep editing the project'})
    return return_message(request, 'Participant removed', [], 'ok', next_actions)


@login_required
def new_viewer(request):
    project_id = request.session['selected_project_id']
    owner_id = request.session['selected_project_owner']
    if (not checkPermissions(request.session['permissions'], 'sysadm', None, None, None, None) and
       (not checkPermissions(request.session['permissions'], 'proadm', None, None, None, None) or owner_id != request.user.user_id)):
        return redirect('/memento')

    if request.method == 'GET':
        request.session['selected_project_viewer_category_id'] = None
        request.session['selected_project_viewer_annotation_id'] = None
        category_id = request.GET.get('category_id', None)
        if (category_id):
            request.session['selected_project_viewer_category_id'] = int(category_id)
        annotation_id = request.GET.get('annotation_id', None)
        if (annotation_id):
            request.session['selected_project_viewer_annotation_id'] = int(annotation_id)
        response = requestAPI(request.user.username, "GET", 'projects/' + str(project_id))
        if (response.status_code == 404):
            next_actions = []
            next_actions.append({ 'url': reverse(views.home), 'text': 'Go back to the main menu'})
            return return_message(request, 'Project not found', [], 'nok', next_actions)

        form = NewViewerForm()
        context = {'form': form}

        context['usernames'] = []
        response = requestAPI(request.user.username, "GET", 'users')
        if (response.status_code == 404):
            next_actions = []
            next_actions.append({ 'url': reverse(views.home), 'text': 'Go back to the main menu'})
            if (annotation_id):
                next_actions.append({ 'url': reverse('edit_annotation') +
                                            '?annotation_id=' + str(annotation_id),
                                      'text': 'Keep editing the annotation'})
            if (category_id):
                next_actions.append({ 'url': reverse('edit_category') +
                                            '?category_id=' + str(category_id),
                                      'text': 'Keep editing the category'})
            next_actions.append({ 'url': reverse('edit_project') +
                                         '?project_id=' + str(project_id),
                                  'text': 'Keep editing the project'})
            return return_message(request, 'No user candidates available to view', [], 'nok', next_actions)

        users_data = response.json()
        users_list =  []
        for curr_user in users_data['users']:
            if (curr_user['user_id'] != owner_id):
                candidate = True
                response_permissions = requestAPI(request.user.username, "GET", 'permissions/byfilter/' + str(curr_user['user_id']) + '/none/0')
                if (response.status_code != 404):
                    permissions_data = response_permissions.json()['permissions']
                    for curr_permission in permissions_data:
                        if ((curr_permission['type'] == 'propar' or curr_permission['type'] == 'provie') and curr_permission['type_id'] == project_id or
                            (curr_permission['type'] == 'catpar' or curr_permission['type'] == 'catvie') and curr_permission['type_id'] == category_id or
                            (curr_permission['type'] == 'annpar' or curr_permission['type'] == 'annvie') and curr_permission['type_id'] == annotation_id):
                            candidate = False
                            break
                if (candidate):
                    users_list.append({'id' : curr_user['user_id'], 'username': curr_user['username']})

            context['usernames'] = users_list
        return render(request, 'memento/new_viewer.html', context)
    if request.method == 'POST':
        form = NewViewerForm(request.POST)
        user_id = form.data['user_id']

        response = requestAPI(request.user.username, "GET", 'users/' + str(user_id))
        if (response.status_code == 404):
            next_actions = []
            next_actions.append({ 'url': reverse(views.home), 'text': 'Go back to the main menu'})
            return return_message(request, 'Viewer not found', [], 'nok', next_actions)

        username = response.json()['user']['username']
        category_id = request.session['selected_project_viewer_category_id']
        annotation_id = request.session['selected_project_viewer_annotation_id']
        stype = 'provie'
        type_id = project_id
        if (annotation_id):
            stype = 'annvie'
            type_id = annotation_id
        elif (category_id):
            stype = 'catvie'
            type_id = category_id

        response = requestAPI(request.user.username, "POST", 'permissions', payload={'user_id': user_id, 'type': stype, 'type_id': type_id})
        next_actions = []
        if (response.status_code != 201):
            next_actions.append({ 'url': reverse(views.home), 'text': 'Go back to the main menu'})
            return return_message(request, 'Could not add viewer', [], 'nok', next_actions)
        else:
            next_actions.append({ 'url': reverse(views.home), 'text': 'Go back to the main menu'})
            next_actions.append({ 'url': reverse('edit_viewer') +
                                         '?username=' + username,
                                  'text': 'Edit the new viewer'})
            if (annotation_id):
                next_actions.append({ 'url': reverse('edit_annotation') +
                                             '?annotation_id=' + str(annotation_id),
                                      'text': 'Keep editing the annotation'})
                next_actions.append({ 'url': reverse('edit_project') +
                                             '?project_id=' + str(project_id),
                                      'text': 'Keep editing the project'})
            if (category_id):
                next_actions.append({ 'url': reverse('edit_category') +
                                             '?category_id=' + str(category_id),
                                      'text': 'Keep editing the category'})
            next_actions.append({ 'url': reverse('edit_project') +
                                         '?project_id=' + str(project_id),
                                  'text': 'Keep editing the project'})
            return return_message(request, 'New viewer added', [], 'ok', next_actions)


@login_required
def edit_viewer(request):
    project_id = request.session['selected_project_id']
    owner_id = request.session['selected_project_owner']
    if (not checkPermissions(request.session['permissions'], 'sysadm', None, None, None, None) and
       (not checkPermissions(request.session['permissions'], 'proadm', None, None, None, None) or owner_id != request.user.user_id)):
        return redirect('/memento')

    if request.method == 'GET':
        request.session['selected_project_viewer_category_id'] = None
        request.session['selected_project_viewer_annotation_id'] = None
        category_id = request.GET.get('category_id', None)
        if (category_id):
            request.session['selected_project_viewer_category_id'] = int(category_id)
        annotation_id = request.GET.get('annotation_id', None)
        if (annotation_id):
            request.session['selected_project_viewer_annotation_id'] = int(annotation_id)
        username = request.GET.get('username', None)
        response = requestAPI(request.user.username, "GET", 'projects/' + str(project_id))
        if (response.status_code == 404):
            next_actions = []
            next_actions.append({ 'url': reverse(views.home), 'text': 'Go back to the main menu'})
            return return_message(request, 'Project not found', [], 'nok', next_actions)

        response = requestAPI(username, "GET", 'users/byusername/' + username)
        if (response.status_code == 404):
            next_actions = []
            next_actions.append({ 'url': reverse(views.home), 'text': 'Go back to the main menu'})
            return return_message(request, 'Viewer not found', [], 'nok', next_actions)
        user_data = response.json()
        user_id = user_data['user']['user_id']
        request.session['selected_project_viewer_id'] = int(user_id)

        context = {'username' : username}
        return render(request, 'memento/edit_viewer.html', context)


def delete_viewer(request):
    project_id = request.session['selected_project_id']
    owner_id = request.session['selected_project_owner']
    if (not checkPermissions(request.session['permissions'], 'sysadm', None, None, None, None) and
       (not checkPermissions(request.session['permissions'], 'proadm', None, None, None, None) or owner_id != request.user.user_id)):
        return redirect('/memento')

    user_id = request.session['selected_project_viewer_id']
    category_id = request.session['selected_project_viewer_category_id']
    annotation_id = request.session['selected_project_viewer_annotation_id']
    stype = 'provie'
    type_id = project_id
    if (annotation_id):
        stype = 'annvie'
        type_id = annotation_id
    elif (category_id):
        stype = 'catvie'
        type_id = category_id

    response = requestAPI(request.user.username, "DELETE", 'permissions/' + str(user_id) + '/' + stype +'/' + str(type_id))

    next_actions = []
    next_actions.append({ 'url': reverse(views.home), 'text': 'Go back to the main menu'})
    if (annotation_id):
        next_actions.append({ 'url': reverse('edit_annotation') +
                                     '?annotation_id=' + str(annotation_id),
                              'text': 'Keep editing the annotation'})
        next_actions.append({ 'url': reverse('edit_project') +
                                     '?project_id=' + str(project_id),
                              'text': 'Keep editing the project'})
    if (category_id):
        next_actions.append({ 'url': reverse('edit_category') +
                                     '?category_id=' + str(category_id),
                              'text': 'Keep editing the category'})
    next_actions.append({ 'url': reverse('edit_project') +
                                '?project_id=' + str(project_id),
                          'text': 'Keep editing the project'})
    return return_message(request, 'Viewer removed', [], 'ok', next_actions)


@login_required
def new_label(request):
    project_id = request.session['selected_project_id']
    owner_id = request.session['selected_project_owner']
    if (not checkPermissions(request.session['permissions'], 'sysadm', None, None, None, None) and
       (not checkPermissions(request.session['permissions'], 'proadm', None, None, None, None) or owner_id != request.user.user_id)):
        return redirect('/memento')

    if request.method == 'GET':
        response = requestAPI(request.user.username, "GET", 'projects/' + str(project_id))
        if (response.status_code == 404):
            next_actions = []
            next_actions.append({ 'url': reverse(views.home), 'text': 'Go back to the main menu'})
            return return_message(request, 'Project not found', [], 'nok', next_actions)

        form = NewLabelForm()
        context = {'form': form}
        return render(request, 'memento/new_label.html', context)
    if request.method == 'POST':
        form = NewLabelForm(request.POST)
        if form.is_valid():
            name = form.cleaned_data.get('name')

            response = requestAPI(request.user.username, "POST", 'labels', payload= {'name': name, 'project_id': project_id, 'owner_id': request.user.user_id})
            next_actions = []
            if (response.status_code != 201):
                next_actions.append({ 'url': reverse(views.home), 'text': 'Go back to the main menu'})
                return return_message(request, 'Could not create label', [], 'nok', next_actions)
            else:
                next_actions.append({ 'url': reverse(views.home), 'text': 'Go back to the main menu'})
                next_actions.append({ 'url': reverse('edit_label') +
                                             '?label_id=' + str(response.json()['label']['label_id']),
                                      'text': 'Edit the new label'})
                next_actions.append({ 'url': reverse('edit_project') +
                                             '?project_id=' + str(project_id),
                                      'text': 'Keep editing the project'})
                return return_message(request, 'New label created', [], 'ok', next_actions)
        else:
            context = {'form': form}
            return render(request, 'memento/new_label.html', context)


@login_required
def edit_label(request):
    project_id = request.session['selected_project_id']
    owner_id = request.session['selected_project_owner']
    if (not checkPermissions(request.session['permissions'], 'sysadm', None, None, None, None) and
       (not checkPermissions(request.session['permissions'], 'proadm', None, None, None, None) or owner_id != request.user.user_id)):
        return redirect('/memento')

    if request.method == 'GET':
        label_id = request.GET.get('label_id', None)
        response = requestAPI(request.user.username, "GET", 'projects/' + str(project_id))
        if (response.status_code == 404):
            next_actions = []
            next_actions.append({ 'url': reverse(views.home), 'text': 'Go back to the main menu'})
            return return_message(request, 'Project not found', [], 'nok', next_actions)

        response = requestAPI(request.user.username, "GET", 'labels/' + str(label_id))
        if (response.status_code == 404):
            next_actions = []
            next_actions.append({ 'url': reverse(views.home), 'text': 'Go back to the main menu'})
            return return_message(request, 'Label not found', [], 'nok', next_actions)
        label_data = response.json()
        if (label_data['label']['project_id'] != project_id):
            return redirect('/memento')
        request.session['selected_project_label_id'] = int(label_id)

        form = NewLabelForm(initial={'name': label_data['label']['name']})
        context = {'form': form}
        return render(request, 'memento/edit_label.html', context)
    if request.method == 'POST':
        form = NewLabelForm(request.POST)
        if form.is_valid():
            label_id = request.session['selected_project_label_id']
            name = form.cleaned_data.get('name')
            response = requestAPI(request.user.username, "GET", 'projects/' + str(project_id))
            if (response.status_code == 404):
                next_actions = []
                next_actions.append({ 'url': reverse(views.home), 'text': 'Go back to the main menu'})
                return return_message(request, 'Project not found', [], 'nok', next_actions)

            response = requestAPI(request.user.username, "GET", 'labels/' + str(label_id))
            if (response.status_code == 404):
                next_actions = []
                next_actions.append({ 'url': reverse(views.home), 'text': 'Go back to the main menu'})
                return return_message(request, 'Label not found', [], 'nok', next_actions)

            label_data = response.json()
            response = requestAPI(request.user.username, "PUT", 'labels/' + str(label_id), payload={'name': name, 'project_id': label_data['label']['project_id'], 'owner_id': label_data['label']['owner_id']})
            next_actions = []
            if (response.status_code != 201):
                next_actions.append({ 'url': reverse(views.home), 'text': 'Go back to the main menu'})
                return return_message(request, 'Could not update label', [], 'nok', next_actions)
            else:
                next_actions.append({ 'url': reverse(views.home), 'text': 'Go back to the main menu'})
                next_actions.append({ 'url': reverse('edit_label') +
                                             '?label_id=' + str(label_id),
                                      'text': 'Edit the label again'})
                next_actions.append({ 'url': reverse('edit_project') +
                                             '?project_id=' + str(project_id),
                                      'text': 'Keep editing the project'})
                return return_message(request, 'Label updated', [], 'ok', next_actions)
        else:
            context = {'form': form}
            return render(request, 'memento/edit_label.html', context)


def delete_label(request):
    project_id = request.session['selected_project_id']
    owner_id = request.session['selected_project_owner']
    if (not checkPermissions(request.session['permissions'], 'sysadm', None, None, None, None) and
       (not checkPermissions(request.session['permissions'], 'proadm', None, None, None, None) or owner_id != request.user.user_id)):
        return redirect('/memento')

    label_id = request.session['selected_project_label_id']
    response = requestAPI(request.user.username, "DELETE", 'labels/' + str(label_id))
    response = requestAPI(request.user.username, "DELETE", 'annotations_labels/byfilter/0/' + str(label_id))

    next_actions = []
    next_actions.append({ 'url': reverse(views.home), 'text': 'Go back to the main menu'})
    next_actions.append({ 'url': reverse('edit_project') +
                                '?project_id=' + str(project_id),
                          'text': 'Keep editing the project'})
    return return_message(request, 'Label removed', [], 'ok', next_actions)


@login_required
def new_category(request):
    project_id = request.session['selected_project_id']
    owner_id = request.session['selected_project_owner']
    if (not checkPermissions(request.session['permissions'], 'sysadm', None, None, None, None) and
       (not checkPermissions(request.session['permissions'], 'proadm', None, None, None, None) or owner_id != request.user.user_id)):
        return redirect('/memento')

    if request.method == 'GET':
        response = requestAPI(request.user.username, "GET", 'projects/' + str(project_id))
        if (response.status_code == 404):
            next_actions = []
            next_actions.append({ 'url': reverse(views.home), 'text': 'Go back to the main menu'})
            return return_message(request, 'Project not found', [], 'nok', next_actions)

        form = NewCategoryForm()
        context = {'form': form}
        return render(request, 'memento/new_category.html', context)
    if request.method == 'POST':
        form = NewCategoryForm(request.POST)
        if form.is_valid():
            name = form.cleaned_data.get('name')

            response = requestAPI(request.user.username, "POST", 'categories', payload={'name': name, 'project_id': project_id, 'owner_id': request.user.user_id, 'settings': ''})

            next_actions = []
            if (response.status_code != 201):
                next_actions.append({ 'url': reverse(views.home), 'text': 'Go back to the main menu'})
                return return_message(request, 'Could not create category', [], 'nok', next_actions)
            else:
                next_actions.append({ 'url': reverse(views.home), 'text': 'Go back to the main menu'})
                next_actions.append({ 'url': reverse('edit_category') +
                                             '?category_id=' + str(response.json()['category']['category_id']),
                                      'text': 'Edit the new category'})
                next_actions.append({ 'url': reverse('edit_project') +
                                             '?project_id=' + str(project_id),
                                      'text': 'Keep editing the project'})
                return return_message(request, 'New category created', [], 'ok', next_actions)
        else:
            context = {'form': form}
            return render(request, 'memento/new_category.html', context)


@login_required
def edit_category(request):
    project_id = request.session['selected_project_id']
    owner_id = request.session['selected_project_owner']
    if (not checkPermissions(request.session['permissions'], 'sysadm', None, None, None, None) and
       (not checkPermissions(request.session['permissions'], 'proadm', None, None, None, None) or owner_id != request.user.user_id)):
        return redirect('/memento')

    if request.method == 'GET':
        category_id = request.GET.get('category_id', None)
        response = requestAPI(request.user.username, "GET", 'projects/' + str(project_id))
        if (response.status_code == 404):
            next_actions = []
            next_actions.append({ 'url': reverse(views.home), 'text': 'Go back to the main menu'})
            return return_message(request, 'Project not found', [], 'nok', next_actions)

        response = requestAPI(request.user.username, "GET", 'categories/' + str(category_id))
        if (response.status_code == 404):
            next_actions = []
            next_actions.append({ 'url': reverse(views.home), 'text': 'Go back to the main menu'})
            return return_message(request, 'Category not found', [], 'nok', next_actions)
        category_data = response.json()
        if (category_data['category']['project_id'] != project_id):
            return redirect('/memento')
        request.session['selected_project_category_id'] = int(category_id)
        request.session['selected_project_participant_annotation_id'] = None

        form = NewCategoryForm(initial={'name': category_data['category']['name'], 'csettings': category_data['category']['settings']})
        context = {'form': form}

        context['maxlengthlist'] = settings.MAXLENGTHLIST
        if ('maxlengthlist' in request.session['settings']):
            context['maxlengthlist'] = request.session['settings']['maxlengthlist']
        context['annotations'] = []

        response = requestAPI(request.user.username, "GET", 'annotations/bycategory_id/' + str(category_id))
        if (response.status_code != 404):
            annotations_data = response.json()
            annotations = []
            for curr_annotation in annotations_data['annotations']:
                annotations.append({'id': curr_annotation['annotation_id'], 'name': curr_annotation['name']})

            context['annotations'] = annotations

        context['participants'] = []
        response = requestAPI(request.user.username, "GET", 'permissions/byfilter/0/catpar/' + str(category_id))
        if (response.status_code != 404):
            permissions_data = response.json()
            participants = []
            for curr_permission in permissions_data['permissions']:
                response_user = requestAPI(request.user.username, "GET", 'users/' + str(curr_permission['user_id']))
                if (response_user.status_code != 404):
                    user_data = response_user.json()
                    participants.append({'id': user_data['user']['user_id'], 'username': user_data['user']['username']})

            context['participants'] = participants

        context['viewers'] = []
        response = requestAPI(request.user.username, "GET", 'permissions/byfilter/0/catvie/' + str(category_id))
        if (response.status_code != 404):
            permissions_data = response.json()
            viewers = []
            for curr_permission in permissions_data['permissions']:
                response_user = requestAPI(request.user.username, "GET", 'users/' + str(curr_permission['user_id']))
                if (response_user.status_code != 404):
                    user_data = response_user.json()
                    viewers.append({'id': user_data['user']['user_id'], 'username': user_data['user']['username']})

            context['viewers'] = viewers

        return render(request, 'memento/edit_category.html', context)
    if request.method == 'POST':
        form = NewCategoryForm(request.POST)
        if form.is_valid():
            category_id = request.session['selected_project_category_id']
            name = form.cleaned_data.get('name')
            csettings = form.cleaned_data.get('csettings')
            if (not csettings):
                csettings = ''
            response = requestAPI(request.user.username, "GET", 'projects/' + str(project_id))
            if (response.status_code == 404):
                next_actions = []
                next_actions.append({ 'url': reverse(views.home), 'text': 'Go back to the main menu'})
                return return_message(request, 'Project not found', [], 'nok', next_actions)

            response = requestAPI(request.user.username, "GET", 'categories/' + str(category_id))
            if (response.status_code == 404):
                next_actions = []
                next_actions.append({ 'url': reverse(views.home), 'text': 'Go back to the main menu'})
                return return_message(request, 'Category not found', [], 'nok', next_actions)

            category_data = response.json()
            response = requestAPI(request.user.username, "PUT", 'categories/' + str(category_id), payload={'name': name, 'settings': csettings, 'project_id': category_data['category']['project_id'],
                                             'owner_id': category_data['category']['owner_id']})
            next_actions = []
            if (response.status_code != 201):
                next_actions.append({ 'url': reverse(views.home), 'text': 'Go back to the main menu'})
                return return_message(request, 'Could not update category', [], 'nok', next_actions)
            else:
                next_actions.append({ 'url': reverse(views.home), 'text': 'Go back to the main menu'})
                next_actions.append({ 'url': reverse('edit_category') +
                                             '?category_id=' + str(category_id),
                                      'text': 'Edit the category again'})
                next_actions.append({ 'url': reverse('edit_project') +
                                             '?project_id=' + str(project_id),
                                      'text': 'Keep editing the project'})
                return return_message(request, 'Category updated', [], 'ok', next_actions)
        else:
            context = {'form': form}
            return render(request, 'memento/edit_category.html', context)


@login_required
def delete_category(request):
    project_id = request.session['selected_project_id']
    owner_id = request.session['selected_project_owner']
    if (not checkPermissions(request.session['permissions'], 'sysadm', None, None, None, None) and
       (not checkPermissions(request.session['permissions'], 'proadm', None, None, None, None) or owner_id != request.user.user_id)):
        return redirect('/memento')

    category_id = request.session['selected_project_category_id']

    response = requestAPI(request.user.username, "GET", 'categories/byproject_id/' + str(project_id))
    if (response.status_code != 404 and len(response.json()['categories']) <= 1):
        next_actions = []
        next_actions.append({ 'url': reverse(views.home), 'text': 'Go back to the main menu'})
        next_actions.append({ 'url': reverse('edit_category') +
                                     '?category_id=' + str(category_id),
                              'text': 'Edit the category again'})
        next_actions.append({ 'url': reverse('edit_project') +
                                     '?project_id=' + str(project_id),
                              'text': 'Keep editing the project'})
        return return_message(request, 'The project must contain at least 1 category', [], 'nok', next_actions)

    response = requestAPI(request.user.username, "DELETE", 'categories/' + str(category_id))
    response = requestAPI(request.user.username, "DELETE", 'permissions/byfilter/0/catpar/' + str(category_id))

    response = requestAPI(request.user.username, "DELETE", 'categories_classifications/byfilter/' + str(category_id) + '/0')

    response = requestAPI(request.user.username, "GET", 'annotations/bycategory_id/' + str(category_id))
    if (response.status_code != 404):
        annotations_data = response.json()
        for curr_annotation in annotations_data['annotations']:
            response = requestAPI(request.user.username, "DELETE", 'annotations/' + str(curr_annotation['annotation_id']))
            response = requestAPI(request.user.username, "DELETE", 'permissions/byfilter/0/annpar/' + str(curr_annotation['annotation_id']))
            response = requestAPI(request.user.username, "DELETE", 'annotations_labels/byfilter/' + str(curr_annotation['annotation_id']) + '/0')

            response = requestAPI(request.user.username, "GET", 'layers/byannotation_id/' + str(curr_annotation['annotation_id']))
            if (response.status_code != 404):
                layers_data = response.json()
                for curr_layer in layers_data['layers']:
                    response = requestAPI(request.user.username, "DELETE", 'layers/' + str(curr_layer['layer_id']))
                    response = requestAPI(request.user.username, "GET", 'comments/bylayer_id/' + str(curr_layer['layer_id']))
                    if (response.status_code != 404):
                        comments_data = response.json()
                        for curr_comment in comments_data['comments']:
                            response = requestAPI(request.user.username, "DELETE", 'comments/' + str(curr_comment['comment_id']))

    next_actions = []
    next_actions.append({ 'url': reverse(views.home), 'text': 'Go back to the main menu'})
    next_actions.append({ 'url': reverse('edit_project') +
                                '?project_id=' + str(project_id),
                          'text': 'Keep editing the project'})
    return return_message(request, 'Category removed', [], 'ok', next_actions)


@login_required
def new_classification(request):
    project_id = request.session['selected_project_id']
    owner_id = request.session['selected_project_owner']
    if (not checkPermissions(request.session['permissions'], 'sysadm', None, None, None, None) and
       (not checkPermissions(request.session['permissions'], 'proadm', None, None, None, None) or owner_id != request.user.user_id)):
        return redirect('/memento')

    if request.method == 'GET':
        response = requestAPI(request.user.username, "GET", 'projects/' + str(project_id))
        if (response.status_code == 404):
            next_actions = []
            next_actions.append({ 'url': reverse(views.home), 'text': 'Go back to the main menu'})
            return return_message(request, 'Project not found', [], 'nok', next_actions)

        form = NewClassificationForm()
        context = {'form': form}
        return render(request, 'memento/new_classification.html', context)
    if request.method == 'POST':
        form = NewClassificationForm(request.POST)
        if form.is_valid():
            name = form.cleaned_data.get('name')
            type = form.cleaned_data.get('type')
            data = form.cleaned_data.get('data')

            response = requestAPI(request.user.username, "POST", 'classifications', payload={'name': name, 'type': type, 'data': data, 'settings': '', 'project_id': project_id, 'owner_id': request.user.user_id})
            next_actions = []
            if (response.status_code != 201):
                next_actions.append({ 'url': reverse(views.home), 'text': 'Go back to the main menu'})
                return return_message(request, 'Could not create classification', [], 'nok', next_actions)
            else:
                next_actions.append({ 'url': reverse(views.home), 'text': 'Go back to the main menu'})
                next_actions.append({ 'url': reverse('edit_classification') +
                                             '?classification_id=' + str(response.json()['classification']['classification_id']),
                                      'text': 'Edit the new classification'})
                next_actions.append({ 'url': reverse('edit_project') +
                                             '?project_id=' + str(project_id),
                                      'text': 'Keep editing the project'})
                return return_message(request, 'New classification created', [], 'ok', next_actions)
        else:
            context = {'form': form}
            return render(request, 'memento/new_classification.html', context)


@login_required
def edit_classification(request):
    project_id = request.session['selected_project_id']
    owner_id = request.session['selected_project_owner']
    if (not checkPermissions(request.session['permissions'], 'sysadm', None, None, None, None) and
       (not checkPermissions(request.session['permissions'], 'proadm', None, None, None, None) or owner_id != request.user.user_id)):
        return redirect('/memento')

    if request.method == 'GET':
        classification_id = request.GET.get('classification_id', None)
        response = requestAPI(request.user.username, "GET", 'projects/' + str(project_id))
        if (response.status_code == 404):
            next_actions = []
            next_actions.append({ 'url': reverse(views.home), 'text': 'Go back to the main menu'})
            return return_message(request, 'Project not found', [], 'nok', next_actions)

        response = requestAPI(request.user.username, "GET", 'classifications/' + str(classification_id))
        if (response.status_code == 404):
            next_actions = []
            next_actions.append({ 'url': reverse(views.home), 'text': 'Go back to the main menu'})
            return return_message(request, 'Classification not found', [], 'nok', next_actions)
        classification_data = response.json()
        if (classification_data['classification']['project_id'] != project_id):
            return redirect('/memento')
        request.session['selected_project_classification_id'] = int(classification_id)

        form = NewClassificationForm(initial={'name': classification_data['classification']['name'], 'type': classification_data['classification']['type'],
                                              'data': classification_data['classification']['data'], 'clsettings': classification_data['classification']['settings']})
        context = {'form': form}
        return render(request, 'memento/edit_classification.html', context)
    if request.method == 'POST':
        form = NewClassificationForm(request.POST)
        if form.is_valid():
            classification_id = request.session['selected_project_classification_id']
            name = form.cleaned_data.get('name')
            type = form.cleaned_data.get('type')
            data = form.cleaned_data.get('data')
            clsettings = form.cleaned_data.get('clsettings')
            if (not clsettings):
                clsettings = ''

            response = requestAPI(request.user.username, "GET", 'projects/' + str(project_id))
            if (response.status_code == 404):
                next_actions = []
                next_actions.append({ 'url': reverse(views.home), 'text': 'Go back to the main menu'})
                return return_message(request, 'Project not found', [], 'nok', next_actions)

            response = requestAPI(request.user.username, "GET", 'classifications/' + str(classification_id))
            if (response.status_code == 404):
                next_actions = []
                next_actions.append({ 'url': reverse(views.home), 'text': 'Go back to the main menu'})
                return return_message(request, 'Classification not found', [], 'nok', next_actions)

            classification_data = response.json()
            response = requestAPI(request.user.username, "PUT", 'classifications/' + str(classification_id),
                                  payload={'name': name, 'type': type, 'data': data, 'settings': clsettings, 'project_id': classification_data['classification']['project_id'], 'owner_id': classification_data['classification']['owner_id']})
            next_actions = []
            if (response.status_code != 201):
                next_actions.append({ 'url': reverse(views.home), 'text': 'Go back to the main menu'})
                return return_message(request, 'Could not update classification', [], 'nok', next_actions)
            else:
                next_actions.append({ 'url': reverse(views.home), 'text': 'Go back to the main menu'})
                next_actions.append({ 'url': reverse('edit_classification') +
                                             '?classification_id=' + str(classification_id),
                                      'text': 'Edit the classification again'})
                next_actions.append({ 'url': reverse('edit_project') +
                                             '?project_id=' + str(project_id),
                                      'text': 'Keep editing the project'})
                return return_message(request, 'Classification updated', [], 'ok', next_actions)
        else:
            context = {'form': form}
            return render(request, 'memento/edit_classification.html', context)


def delete_classification(request):
    project_id = request.session['selected_project_id']
    owner_id = request.session['selected_project_owner']
    if (not checkPermissions(request.session['permissions'], 'sysadm', None, None, None, None) and
       (not checkPermissions(request.session['permissions'], 'proadm', None, None, None, None) or owner_id != request.user.user_id)):
        return redirect('/memento')

    classification_id = request.session['selected_project_classification_id']
    response = requestAPI(request.user.username, "DELETE", 'classifications/' + str(classification_id))
    response = requestAPI(request.user.username, "DELETE", 'categories_classifications/byfilter/0/' + str(classification_id))

    next_actions = []
    next_actions.append({ 'url': reverse(views.home), 'text': 'Go back to the main menu'})
    next_actions.append({ 'url': reverse('edit_project') +
                                '?project_id=' + str(project_id),
                          'text': 'Keep editing the project'})
    return return_message(request, 'Classification removed', [], 'ok', next_actions)


@login_required
def new_image(request):
    project_id = request.session['selected_project_id']
    owner_id = request.session['selected_project_owner']
    if (not checkPermissions(request.session['permissions'], 'sysadm', None, None, None, None) and
       (not checkPermissions(request.session['permissions'], 'proadm', None, None, None, None) or owner_id != request.user.user_id)):
        return redirect('/memento')

    if request.method == 'GET':
        response = requestAPI(request.user.username, "GET", 'projects/' + str(project_id))
        if (response.status_code == 404):
            next_actions = []
            next_actions.append({ 'url': reverse(views.home), 'text': 'Go back to the main menu'})
            return return_message(request, 'Project not found', [], 'nok', next_actions)

        form = NewImageForm()
        context = {'form': form}
        context['formats'] = [{'id': 1, 'description': 'Fast'}, {'id': 2, 'description': 'Fast with transparency'}, {'id': 4, 'description': 'Tiled image'}, {'id': 5, 'description': 'Tiled image with transparency'}, {'id': 3, 'description': 'Maximum quality'}]
        return render(request, 'memento/new_image.html', context)
    if request.method == 'POST':
        form = NewImageForm(request.POST, request.FILES)
        name = form.data['name']
        img_format = form.data['format']
        uri = form.data['url']

        if ((not uri or uri == '') and '/' in request.FILES['file'].name):
            next_actions = []
            next_actions.append({ 'url': reverse(views.home), 'text': 'Go back to the main menu'})
            return return_message_content(request, 'Could not create image', [], 'nok', next_actions)

        response = None
        if (uri and uri != ''):
            response = requestAPI(request.user.username, "POST", 'images', payload={'filepath' : '', 'format' : 0, 'name': name, 'uri': uri, 'type': 'E', 'project_id': project_id, 'owner_id': request.user.user_id})
        else:
            filepath = settings.IMAGES_ROOT + '/' + request.FILES['file'].name.replace(' ', '_')
            with open(filepath, 'wb+') as destination:
                for chunk in request.FILES['file'].chunks():
                    destination.write(chunk)
            uri = 'temp'
            type = ''
            if (img_format == 5 or img_format == '5' or img_format == 4 or img_format == '4'):
                type = 'T'
            response = requestAPI(request.user.username, "POST", 'images', payload={'filepath' : filepath, 'format': img_format, 'name': name, 'uri': uri, 'type': type, 'project_id': project_id, 'owner_id': request.user.user_id})
            os.remove(filepath)

        if (response.status_code != 201):
            next_actions = []
            next_actions.append({ 'url': reverse(views.home), 'text': 'Go back to the main menu'})
            return return_message_content(request, 'Could not create image', [], 'nok', next_actions)
        else:
            image_data = response.json()['image']
            image_id = image_data['image_id']

            next_actions = []
            next_actions.append({ 'url': reverse(views.home), 'text': 'Go back to the main menu'})
            next_actions.append({ 'url': reverse('edit_image') +
                                         '?image_id=' + str(image_id),
                                  'text': 'Edit the new image'})
            next_actions.append({ 'url': reverse('edit_project') +
                                         '?project_id=' + str(project_id),
                                  'text': 'Keep editing the project'})
            return return_message_content(request, 'New image created', [], 'ok', next_actions)


@login_required
def edit_image(request):
    project_id = request.session['selected_project_id']
    owner_id = request.session['selected_project_owner']
    if (not checkPermissions(request.session['permissions'], 'sysadm', None, None, None, None) and
       (not checkPermissions(request.session['permissions'], 'proadm', None, None, None, None) or owner_id != request.user.user_id)):
        return redirect('/memento')

    if request.method == 'GET':
        image_id = request.GET.get('image_id', None)
        response = requestAPI(request.user.username, "GET", 'projects/' + str(project_id))
        if (response.status_code == 404):
            next_actions = []
            next_actions.append({ 'url': reverse(views.home), 'text': 'Go back to the main menu'})
            return return_message(request, 'Project not found', [], 'nok', next_actions)

        response = requestAPI(request.user.username, "GET", 'images/' + str(image_id))
        if (response.status_code == 404):
            next_actions = []
            next_actions.append({ 'url': reverse(views.home), 'text': 'Go back to the main menu'})
            return return_message(request, 'Image not found', [], 'nok', next_actions)
        images_data = response.json()
        if (images_data['image']['project_id'] != project_id):
            return redirect('/memento')
        request.session['selected_project_image_id'] = int(image_id)

        allowed_images = []
        allowed_images.append(int(image_id))
        request.session['allowed_images'] = allowed_images

        form = NewImageForm(initial={'name': images_data['image']['name']})
        context = {'form': form}
        context['image_uri'] = images_data['image']['uri']
        context['image_type'] = images_data['image']['type']
        return render(request, 'memento/edit_image.html', context)
    if request.method == 'POST':
        form = EditImageForm(request.POST)
        if form.is_valid():
            image_id = request.session['selected_project_image_id']
            name = form.cleaned_data.get('name')
            response = requestAPI(request.user.username, "GET", 'projects/' + str(project_id))
            if (response.status_code == 404):
                next_actions = []
                next_actions.append({ 'url': reverse(views.home), 'text': 'Go back to the main menu'})
                return return_message(request, 'Project not found', [], 'nok', next_actions)

            response = requestAPI(request.user.username, "GET", 'images/' + str(image_id))
            if (response.status_code == 404):
                next_actions = []
                next_actions.append({ 'url': reverse(views.home), 'text': 'Go back to the main menu'})
                return return_message(request, 'Image not found', [], 'nok', next_actions)

            images_data = response.json()
            response = requestAPI(request.user.username, "PUT", 'images/' + str(image_id), payload={'name': name, 'uri': images_data['image']['uri'], 'type': images_data['image']['type'], 'project_id': images_data['image']['project_id'],
                                             'owner_id': images_data['image']['owner_id']})
            next_actions = []
            if (response.status_code != 201):
                next_actions.append({ 'url': reverse(views.home), 'text': 'Go back to the main menu'})
                return return_message(request, 'Could not update image', [], 'nok', next_actions)
            else:
                next_actions.append({ 'url': reverse(views.home), 'text': 'Go back to the main menu'})
                next_actions.append({ 'url': reverse('edit_image') +
                                             '?image_id=' + str(image_id),
                                      'text': 'Edit the image again'})
                next_actions.append({ 'url': reverse('edit_project') +
                                             '?project_id=' + str(project_id),
                                      'text': 'Keep editing the project'})
                return return_message(request, 'Image updated', [], 'ok', next_actions)
        else:
            next_actions = []
            next_actions.append({ 'url': reverse(views.home), 'text': 'Go back to the main menu'})
            return return_message_content(request, 'Could not edit image', [], 'nok', next_actions)


@login_required
def delete_image(request):
    project_id = request.session['selected_project_id']
    owner_id = request.session['selected_project_owner']
    if (not checkPermissions(request.session['permissions'], 'sysadm', None, None, None, None) and
       (not checkPermissions(request.session['permissions'], 'proadm', None, None, None, None) or owner_id != request.user.user_id)):
        return redirect('/memento')

    image_id = request.session['selected_project_image_id']
    response = requestAPI(request.user.username, "GET", 'images/' + str(image_id))
    if (response.status_code != 404):
        image_data = response.json()

        response = requestAPI(request.user.username, "DELETE", 'images/' + str(image_id))

        response = requestAPI(request.user.username, "GET", 'annotations/byimage_id/' + str(image_id))
        if (response.status_code != 404):
            annotations_data = response.json()
            for curr_annotation in annotations_data['annotations']:
                response = requestAPI(request.user.username, "DELETE", 'annotations/' + str(curr_annotation['annotation_id']))
                response = requestAPI(request.user.username, "DELETE", 'permissions/byfilter/0/annpar/' + str(curr_annotation['annotation_id']))
                response = requestAPI(request.user.username, "DELETE", 'annotations_labels/byfilter/' + str(curr_annotation['annotation_id']) + '/0')

                response = requestAPI(request.user.username, "GET", 'layers/byannotation_id/' + str(curr_annotation['annotation_id']))
                if (response.status_code != 404):
                    layers_data = response.json()
                    for curr_layer in layers_data['layers']:
                        response = requestAPI(request.user.username, "DELETE", 'layers/' + str(curr_layer['layer_id']))
                        response = requestAPI(request.user.username, "GET", 'comments/bylayer_id/' + str(curr_layer['layer_id']))
                        if (response.status_code != 404):
                            comments_data = response.json()
                            for curr_comment in comments_data['comments']:
                                response = requestAPI(request.user.username, "DELETE", 'comments/' + str(curr_comment['comment_id']))

        response = requestAPI(request.user.username, "GET", 'layers/byimage_id/' + str(image_id))
        if (response.status_code != 404):
            layers_data = response.json()
            for curr_layer in layers_data['layers']:
                response = requestAPI(request.user.username, "DELETE", 'layers/' + str(curr_layer['layer_id']))
                response = requestAPI(request.user.username, "GET", 'comments/bylayer_id/' + str(curr_layer['layer_id']))
                if (response.status_code != 404):
                    comments_data = response.json()
                    for curr_comment in comments_data['comments']:
                        response = requestAPI(request.user.username, "DELETE", 'comments/' + str(curr_comment['comment_id']))

    next_actions = []
    next_actions.append({ 'url': reverse(views.home), 'text': 'Go back to the main menu'})
    next_actions.append({ 'url': reverse('edit_project') +
                                '?project_id=' + str(project_id),
                          'text': 'Keep editing the project'})
    return return_message(request, 'Image removed', [], 'ok', next_actions)


@login_required
def new_annotation(request):
    project_id = request.session['selected_project_id']
    category_id = request.session['selected_project_category_id']
    owner_id = request.session['selected_project_owner']
    if (not checkPermissions(request.session['permissions'], 'sysadm', None, None, None, None) and
       (not checkPermissions(request.session['permissions'], 'proadm', None, None, None, None) or owner_id != request.user.user_id)):
        return redirect('/memento')

    if request.method == 'GET':
        response = requestAPI(request.user.username, "GET", 'projects/' + str(project_id))
        if (response.status_code == 404):
            next_actions = []
            next_actions.append({ 'url': reverse(views.home), 'text': 'Go back to the main menu'})
            return return_message(request, 'Project not found', [], 'nok', next_actions)

        response = requestAPI(request.user.username, "GET", 'categories/' + str(category_id))
        if (response.status_code == 404):
            next_actions = []
            next_actions.append({ 'url': reverse(views.home), 'text': 'Go back to the main menu'})
            return return_message(request, 'Category not found', [], 'nok', next_actions)

        form = NewAnnotationForm()
        context = {'form': form}

        context['images'] = []
        response = requestAPI(request.user.username, "GET", 'images/byproject_id/' + str(project_id))
        if (response.status_code == 404):
            next_actions = []
            next_actions.append({ 'url': reverse(views.home), 'text': 'Go back to the main menu'})
            next_actions.append({ 'url': reverse('edit_category') +
                                         '?category_id=' + str(category_id),
                                  'text': 'Keep editing the category'})
            next_actions.append({ 'url': reverse('edit_project') +
                                         '?project_id=' + str(project_id),
                                  'text': 'Keep editing the project'})
            return return_message(request, 'No image candidates available to annotate', [], 'nok', next_actions)

        images_data = response.json()
        images_list = []
        for curr_image in images_data['images']:
            images_list.append({'id' : curr_image['image_id'], 'name': curr_image['name']})

        context['images'] = images_list

        return render(request, 'memento/new_annotation.html', context)
    if request.method == 'POST':
        form = NewAnnotationForm(request.POST)
        if form.is_valid():
            category_id = request.session['selected_project_category_id']
            name = form.cleaned_data.get('name')
            image_id = form.cleaned_data.get('image_id')

            response = requestAPI(request.user.username, "POST", 'annotations', payload={'name': name, 'status' : 'N', 'shared' : '', 'image_id': image_id, 'project_id': project_id,
                                             'category_id': category_id, 'owner_id': request.user.user_id})
            annotation_id = response.json()['annotation']['annotation_id']

            response = requestAPI(request.user.username, "POST", 'layers', payload={'name': 'base', 'data': '', 'image_id': image_id, 'sequence': 1, 'parent_id': 0, 'annotation_id': annotation_id, 'owner_id': request.user.user_id})

            next_actions = []
            if (response.status_code != 201):
                next_actions.append({ 'url': reverse(views.home), 'text': 'Go back to the main menu'})
                return return_message(request, 'Could not create annotation', [], 'nok', next_actions)
            else:
                next_actions.append({ 'url': reverse(views.home), 'text': 'Go back to the main menu'})
                next_actions.append({ 'url': reverse('edit_annotation') +
                                             '?annotation_id=' + str(annotation_id),
                                      'text': 'Edit the new annotation'})
                next_actions.append({ 'url': reverse('edit_category') +
                                             '?category_id=' + str(category_id),
                                      'text': 'Keep editing the category'})
                next_actions.append({ 'url': reverse('edit_project') +
                                             '?project_id=' + str(project_id),
                                      'text': 'Keep editing the project'})
                return return_message(request, 'New annotation created', [], 'ok', next_actions)
        else:
            context = {'form': form}
            return render(request, 'memento/new_annotation.html', context)


@login_required
def edit_annotation(request):
    project_id = request.session['selected_project_id']
    category_id = request.session['selected_project_category_id']
    owner_id = request.session['selected_project_owner']
    if (not checkPermissions(request.session['permissions'], 'sysadm', None, None, None, None) and
       (not checkPermissions(request.session['permissions'], 'proadm', None, None, None, None) or owner_id != request.user.user_id)):
        return redirect('/memento')

    if request.method == 'GET':
        annotation_id = request.GET.get('annotation_id', None)
        response = requestAPI(request.user.username, "GET", 'projects/' + str(project_id))
        if (response.status_code == 404):
            next_actions = []
            next_actions.append({ 'url': reverse(views.home), 'text': 'Go back to the main menu'})
            return return_message(request, 'Project not found', [], 'nok', next_actions)

        response = requestAPI(request.user.username, "GET", 'categories/' + str(category_id))
        if (response.status_code == 404):
            next_actions = []
            next_actions.append({ 'url': reverse(views.home), 'text': 'Go back to the main menu'})
            return return_message(request, 'Category not found', [], 'nok', next_actions)

        response = requestAPI(request.user.username, "GET", 'annotations/' + str(annotation_id))
        if (response.status_code == 404):
            next_actions = []
            next_actions.append({ 'url': reverse(views.home), 'text': 'Go back to the main menu'})
            return return_message(request, 'Annotation not found', [], 'nok', next_actions)
        annotations_data = response.json()
        if (annotations_data['annotation']['project_id'] != project_id or
            annotations_data['annotation']['category_id'] != category_id):
            return redirect('/memento')
        request.session['selected_project_annotation_id'] = int(annotation_id)

        form = NewAnnotationForm(initial={'name': annotations_data['annotation']['name'], 'image_id': annotations_data['annotation']['image_id'],
                                          'status': annotations_data['annotation']['status']})
        context = {'form': form}
        context['sharedURL'] = ''
        if (annotations_data['annotation']['shared'] != ''):
            context['sharedURL'] = (request.build_absolute_uri('viewer') + '?project_id=' + str(project_id) + '&category_id=' + str(category_id) +
                                                                               '&annotation_id=' + str(annotation_id) + '&share=' + annotations_data['annotation']['shared'])

        context['maxlengthlist'] = settings.MAXLENGTHLIST
        if ('maxlengthlist' in request.session['settings']):
            context['maxlengthlist'] = request.session['settings']['maxlengthlist']
        context['images'] = []
        response = requestAPI(request.user.username, "GET", 'images/byproject_id/' + str(project_id))
        if (response.status_code == 404):
            next_actions = []
            next_actions.append({ 'url': reverse(views.home), 'text': 'Go back to the main menu'})
            next_actions.append({ 'url': reverse('edit_category') +
                                         '?category_id=' + str(category_id),
                                  'text': 'Keep editing the category'})
            next_actions.append({ 'url': reverse('edit_project') +
                                         '?project_id=' + str(project_id),
                                  'text': 'Keep editing the project'})
            return return_message(request, 'No image candidates available to annotate', [], 'nok', next_actions)

        images_data = response.json()
        images_list =  []
        for curr_image in images_data['images']:
            images_list.append({'id' : curr_image['image_id'], 'name': curr_image['name']})

        context['images'] = images_list

        context['status'] = [{'id': 'N', 'description': 'None'}, {'id': 'S', 'description': 'Submitted'}]

        context['participants'] = []
        response = requestAPI(request.user.username, "GET", 'permissions/byfilter/0/annpar/' + str(annotation_id))
        if (response.status_code != 404):
            permissions_data = response.json()
            participants = []
            for curr_permission in permissions_data['permissions']:
                response_user = requestAPI(request.user.username, "GET", 'users/' + str(curr_permission['user_id']))
                if (response_user.status_code != 404):
                    user_data = response_user.json()
                    participants.append({'id': user_data['user']['user_id'], 'username': user_data['user']['username']})

            context['participants'] = participants

        context['viewers'] = []
        response = requestAPI(request.user.username, "GET", 'permissions/byfilter/0/annvie/' + str(annotation_id))
        if (response.status_code != 404):
            permissions_data = response.json()
            viewers = []
            for curr_permission in permissions_data['permissions']:
                response_user = requestAPI(request.user.username, "GET", 'users/' + str(curr_permission['user_id']))
                if (response_user.status_code != 404):
                    user_data = response_user.json()
                    viewers.append({'id': user_data['user']['user_id'], 'username': user_data['user']['username']})

            context['viewers'] = viewers

        context['layers'] = []
        response = requestAPI(request.user.username, "GET", 'layers/byannotation_id/' + str(annotation_id))
        if (response.status_code != 404):
            layers_data = response.json()
            layers = []
            for curr_layer in layers_data['layers']:
                layers.append({'id': curr_layer['layer_id'], 'name': curr_layer['name'], 'image_id': curr_layer['image_id']})

            context['layers'] = layers

        return render(request, 'memento/edit_annotation.html', context)
    if request.method == 'POST':
        form = NewAnnotationForm(request.POST)
        if form.is_valid():
            annotation_id = request.session['selected_project_annotation_id']
            name = form.cleaned_data.get('name')
            image_id = form.cleaned_data.get('image_id')
            status = form.cleaned_data.get('status')
            response = requestAPI(request.user.username, "GET", 'projects/' + str(project_id))
            if (response.status_code == 404):
                next_actions = []
                next_actions.append({ 'url': reverse(views.home), 'text': 'Go back to the main menu'})
                return return_message(request, 'Project not found', [], 'nok', next_actions)

            response = requestAPI(request.user.username, "GET", 'categories/' + str(category_id))
            if (response.status_code == 404):
                next_actions = []
                next_actions.append({ 'url': reverse(views.home), 'text': 'Go back to the main menu'})
                return return_message(request, 'Category not found', [], 'nok', next_actions)

            response = requestAPI(request.user.username, "GET", 'images/' + str(image_id))
            if (response.status_code == 404):
                next_actions = []
                next_actions.append({ 'url': reverse(views.home), 'text': 'Go back to the main menu'})
                return return_message(request, 'Image not found', [], 'nok', next_actions)

            response = requestAPI(request.user.username, "GET", 'annotations/' + str(annotation_id))
            if (response.status_code == 404):
                next_actions = []
                next_actions.append({ 'url': reverse(views.home), 'text': 'Go back to the main menu'})
                return return_message(request, 'Annotation not found', [], 'nok', next_actions)

            annotations_data = response.json()
            response = requestAPI(request.user.username, "PUT", 'annotations/' + str(annotation_id), payload={'name': name, 'status': status, 'shared': annotations_data['annotation']['shared'],
                                             'image_id': image_id, 'project_id': annotations_data['annotation']['project_id'],
                                             'category_id': annotations_data['annotation']['category_id'],
                                             'owner_id': annotations_data['annotation']['owner_id']})
            next_actions = []
            if (response.status_code != 201):
                next_actions.append({ 'url': reverse(views.home), 'text': 'Go back to the main menu'})
                return return_message(request, 'Could not update annotation', [], 'nok', next_actions)
            else:
                next_actions.append({ 'url': reverse(views.home), 'text': 'Go back to the main menu'})
                next_actions.append({ 'url': reverse('edit_annotation') +
                                             '?annotation_id=' + str(annotation_id),
                                      'text': 'Edit the annotation again'})
                next_actions.append({ 'url': reverse('edit_category') +
                                             '?category_id=' + str(category_id),
                                      'text': 'Keep editing the category'})
                next_actions.append({ 'url': reverse('edit_project') +
                                             '?project_id=' + str(project_id),
                                      'text': 'Keep editing the project'})
                return return_message(request, 'Annotation updated', [], 'ok', next_actions)
        else:
            context = {'form': form}
            return render(request, 'memento/edit_annotation.html', context)


@login_required
def delete_annotation(request):
    project_id = request.session['selected_project_id']
    category_id = request.session['selected_project_category_id']
    owner_id = request.session['selected_project_owner']
    if (not checkPermissions(request.session['permissions'], 'sysadm', None, None, None, None) and
       (not checkPermissions(request.session['permissions'], 'proadm', None, None, None, None) or owner_id != request.user.user_id)):
        return redirect('/memento')

    annotation_id = request.session['selected_project_annotation_id']
    response = requestAPI(request.user.username, "DELETE", 'annotations/' + str(annotation_id))
    response = requestAPI(request.user.username, "DELETE", 'permissions/byfilter/0/annpar/' + str(annotation_id))
    response = requestAPI(request.user.username, "DELETE", 'annotations_labels/byfilter/' + str(annotation_id) + '/0')

    response = requestAPI(request.user.username, "GET", 'layers/byannotation_id/' + str(annotation_id))
    if (response.status_code != 404):
        layers_data = response.json()
        for curr_layer in layers_data['layers']:
            response = requestAPI(request.user.username, "DELETE", 'layers/' + str(curr_layer['layer_id']))
            response = requestAPI(request.user.username, "GET", 'comments/bylayer_id/' + str(curr_layer['layer_id']))
            if (response.status_code != 404):
                comments_data = response.json()
                for curr_comment in comments_data['comments']:
                    response = requestAPI(request.user.username, "DELETE", 'comments/' + str(curr_comment['comment_id']))

    next_actions = []
    next_actions.append({ 'url': reverse(views.home), 'text': 'Go back to the main menu'})
    next_actions.append({ 'url': reverse('edit_category') +
                                 '?category_id=' + str(category_id),
                          'text': 'Keep editing the category'})
    next_actions.append({ 'url': reverse('edit_project') +
                                '?project_id=' + str(project_id),
                          'text': 'Keep editing the project'})
    return return_message(request, 'Annotation removed', [], 'ok', next_actions)


@login_required
def new_layer(request):
    project_id = request.session['selected_project_id']
    category_id = request.session['selected_project_category_id']
    annotation_id = request.session['selected_project_annotation_id']
    owner_id = request.session['selected_project_owner']
    if (not checkPermissions(request.session['permissions'], 'sysadm', None, None, None, None) and
       (not checkPermissions(request.session['permissions'], 'proadm', None, None, None, None) or owner_id != request.user.user_id)):
        return redirect('/memento')

    if request.method == 'GET':
        response = requestAPI(request.user.username, "GET", 'projects/' + str(project_id))
        if (response.status_code == 404):
            next_actions = []
            next_actions.append({ 'url': reverse(views.home), 'text': 'Go back to the main menu'})
            return return_message(request, 'Project not found', [], 'nok', next_actions)

        response = requestAPI(request.user.username, "GET", 'categories/' + str(category_id))
        if (response.status_code == 404):
            next_actions = []
            next_actions.append({ 'url': reverse(views.home), 'text': 'Go back to the main menu'})
            return return_message(request, 'Category not found', [], 'nok', next_actions)

        response = requestAPI(request.user.username, "GET", 'annotations/' + str(annotation_id))
        if (response.status_code == 404):
            next_actions = []
            next_actions.append({ 'url': reverse(views.home), 'text': 'Go back to the main menu'})
            return return_message(request, 'Annotation not found', [], 'nok', next_actions)

        form = NewLayerForm()
        context = {'form': form}

        context['images'] = []
        response = requestAPI(request.user.username, "GET", 'images/byproject_id/' + str(project_id))
        if (response.status_code == 404):
            next_actions = []
            next_actions.append({ 'url': reverse(views.home), 'text': 'Go back to the main menu'})
            next_actions.append({ 'url': reverse('edit_annotation') +
                                         '?annotation_id=' + str(annotation_id),
                                  'text': 'Keep editing the annotation'})
            next_actions.append({ 'url': reverse('edit_category') +
                                         '?category_id=' + str(category_id),
                                  'text': 'Keep editing the category'})
            next_actions.append({ 'url': reverse('edit_project') +
                                         '?project_id=' + str(project_id),
                                  'text': 'Keep editing the project'})
            return return_message(request, 'No image candidates available to assign to a layer', [], 'nok', next_actions)

        images_data = response.json()
        images_list = []
        images_list.append({'id' : 0, 'name': 'None'})
        for curr_image in images_data['images']:
            images_list.append({'id' : curr_image['image_id'], 'name': curr_image['name']})

        context['images'] = images_list

        return render(request, 'memento/new_layer.html', context)
    if request.method == 'POST':
        form = NewLayerForm(request.POST)
        if form.is_valid():
            annotation_id = request.session['selected_project_annotation_id']
            name = form.cleaned_data.get('name')
            image_id = form.cleaned_data.get('image_id')

            response = requestAPI(request.user.username, "GET", 'layers/byannotation_id/' + str(annotation_id))
            if (response.status_code == 404):
                return HttpResponse('nok')
            layers_data = response.json()['layers']

            curr_sequence = (layers_data[len(layers_data) - 1]['sequence'] + 1)
            response = requestAPI(request.user.username, "POST", 'layers', payload={'name': name, 'data': '', 'image_id': image_id, 'sequence': curr_sequence, 'parent_id': 0, 'annotation_id': annotation_id, 'owner_id' : request.user.user_id})

            next_actions = []
            if (response.status_code != 201):
                next_actions.append({ 'url': reverse(views.home), 'text': 'Go back to the main menu'})
                return return_message(request, 'Could not create layer', [], 'nok', next_actions)
            else:
                next_actions.append({ 'url': reverse(views.home), 'text': 'Go back to the main menu'})
                next_actions.append({ 'url': reverse('edit_layer') +
                                             '?layer_id=' + str(response.json()['layer']['layer_id']),
                                      'text': 'Edit the new layer'})
                next_actions.append({ 'url': reverse('edit_annotation') +
                                             '?annotation_id=' + str(annotation_id),
                                      'text': 'Keep editing the annotation'})
                next_actions.append({ 'url': reverse('edit_category') +
                                             '?category_id=' + str(category_id),
                                      'text': 'Keep editing the category'})
                next_actions.append({ 'url': reverse('edit_project') +
                                             '?project_id=' + str(project_id),
                                      'text': 'Keep editing the project'})
                return return_message(request, 'New annotation created', [], 'ok', next_actions)
        else:
            context = {'form': form}
            return render(request, 'memento/new_layer.html', context)


@login_required
def edit_layer(request):
    project_id = request.session['selected_project_id']
    category_id = request.session['selected_project_category_id']
    annotation_id = request.session['selected_project_annotation_id']
    owner_id = request.session['selected_project_owner']
    if (not checkPermissions(request.session['permissions'], 'sysadm', None, None, None, None) and
       (not checkPermissions(request.session['permissions'], 'proadm', None, None, None, None) or owner_id != request.user.user_id)):
        return redirect('/memento')

    if request.method == 'GET':
        layer_id = request.GET.get('layer_id', None)
        response = requestAPI(request.user.username, "GET", 'projects/' + str(project_id))
        if (response.status_code == 404):
            next_actions = []
            next_actions.append({ 'url': reverse(views.home), 'text': 'Go back to the main menu'})
            return return_message(request, 'Project not found', [], 'nok', next_actions)

        response = requestAPI(request.user.username, "GET", 'categories/' + str(category_id))
        if (response.status_code == 404):
            next_actions = []
            next_actions.append({ 'url': reverse(views.home), 'text': 'Go back to the main menu'})
            return return_message(request, 'Category not found', [], 'nok', next_actions)

        response = requestAPI(request.user.username, "GET", 'annotations/' + str(annotation_id))
        if (response.status_code == 404):
            next_actions = []
            next_actions.append({ 'url': reverse(views.home), 'text': 'Go back to the main menu'})
            return return_message(request, 'Annotation not found', [], 'nok', next_actions)

        response = requestAPI(request.user.username, "GET", 'layers/' + str(layer_id))
        if (response.status_code == 404):
            next_actions = []
            next_actions.append({ 'url': reverse(views.home), 'text': 'Go back to the main menu'})
            return return_message(request, 'Layer not found', [], 'nok', next_actions)
        layers_data = response.json()
        if (layers_data['layer']['annotation_id'] != annotation_id or layers_data['layer']['sequence'] == 1):
            return redirect('/memento')
        request.session['selected_project_layer_id'] = int(layer_id)

        form = NewLayerForm(initial={'name': layers_data['layer']['name'], 'image_id': layers_data['layer']['image_id']})
        context = {'form': form}

        context['maxlengthlist'] = settings.MAXLENGTHLIST
        if ('maxlengthlist' in request.session['settings']):
            context['maxlengthlist'] = request.session['settings']['maxlengthlist']
        context['images'] = []
        response = requestAPI(request.user.username, "GET", 'images/byproject_id/' + str(project_id))
        if (response.status_code == 404):
            next_actions = []
            next_actions.append({ 'url': reverse(views.home), 'text': 'Go back to the main menu'})
            next_actions.append({ 'url': reverse('edit_annotation') +
                                         '?annotation_id=' + str(annotation_id),
                                  'text': 'Keep editing the annotation'})
            next_actions.append({ 'url': reverse('edit_category') +
                                         '?category_id=' + str(category_id),
                                  'text': 'Keep editing the category'})
            next_actions.append({ 'url': reverse('edit_project') +
                                         '?project_id=' + str(project_id),
                                  'text': 'Keep editing the project'})
            return return_message(request, 'No image candidates available to assign to a layer', [], 'nok', next_actions)

        images_data = response.json()
        images_list =  []
        images_list.append({'id' : 0, 'name': 'None'})
        for curr_image in images_data['images']:
            images_list.append({'id' : curr_image['image_id'], 'name': curr_image['name']})

        context['images'] = images_list

        return render(request, 'memento/edit_layer.html', context)
    if request.method == 'POST':
        form = NewLayerForm(request.POST)
        if form.is_valid():
            layer_id = request.session['selected_project_layer_id']
            name = form.cleaned_data.get('name')
            image_id = form.cleaned_data.get('image_id')
            response = requestAPI(request.user.username, "GET", 'projects/' + str(project_id))
            if (response.status_code == 404):
                next_actions = []
                next_actions.append({ 'url': reverse(views.home), 'text': 'Go back to the main menu'})
                return return_message(request, 'Project not found', [], 'nok', next_actions)

            response = requestAPI(request.user.username, "GET", 'categories/' + str(category_id))
            if (response.status_code == 404):
                next_actions = []
                next_actions.append({ 'url': reverse(views.home), 'text': 'Go back to the main menu'})
                return return_message(request, 'Category not found', [], 'nok', next_actions)

            if (image_id > 0):
                response = requestAPI(request.user.username, "GET", 'images/' + str(image_id))
                if (response.status_code == 404):
                    next_actions = []
                    next_actions.append({ 'url': reverse(views.home), 'text': 'Go back to the main menu'})
                    return return_message(request, 'Image not found', [], 'nok', next_actions)

            response = requestAPI(request.user.username, "GET", 'annotations/' + str(annotation_id))
            if (response.status_code == 404):
                next_actions = []
                next_actions.append({ 'url': reverse(views.home), 'text': 'Go back to the main menu'})
                return return_message(request, 'Annotation not found', [], 'nok', next_actions)

            response = requestAPI(request.user.username, "GET", 'layers/' + str(layer_id))
            if (response.status_code == 404):
                next_actions = []
                next_actions.append({ 'url': reverse(views.home), 'text': 'Go back to the main menu'})
                return return_message(request, 'Layer not found', [], 'nok', next_actions)

            layers_data = response.json()
            response = requestAPI(request.user.username, "PUT", 'layers/' + str(layer_id), payload={'name': name, 'data': layers_data['layer']['data'], 'image_id': image_id, 'sequence': layers_data['layer']['sequence'],
                                             'parent_id': 0, 'annotation_id': layers_data['layer']['annotation_id'], 'owner_id' : layers_data['layer']['owner_id']})
            next_actions = []
            if (response.status_code != 201):
                next_actions.append({ 'url': reverse(views.home), 'text': 'Go back to the main menu'})
                return return_message(request, 'Could not update layer', [], 'nok', next_actions)
            else:
                next_actions.append({ 'url': reverse(views.home), 'text': 'Go back to the main menu'})
                next_actions.append({ 'url': reverse('edit_layer') +
                                             '?layer_id=' + str(layer_id),
                                      'text': 'Edit the layer again'})
                next_actions.append({ 'url': reverse('edit_annotation') +
                                             '?annotation_id=' + str(annotation_id),
                                      'text': 'Keep editing the annotation'})
                next_actions.append({ 'url': reverse('edit_category') +
                                             '?category_id=' + str(category_id),
                                      'text': 'Keep editing the category'})
                next_actions.append({ 'url': reverse('edit_project') +
                                             '?project_id=' + str(project_id),
                                      'text': 'Keep editing the project'})
                return return_message(request, 'Layer updated', [], 'ok', next_actions)
        else:
            context = {'form': form}
            return render(request, 'memento/edit_layer.html', context)


@login_required
def delete_layer(request):
    project_id = request.session['selected_project_id']
    category_id = request.session['selected_project_category_id']
    annotation_id = request.session['selected_project_annotation_id']
    owner_id = request.session['selected_project_owner']
    if (not checkPermissions(request.session['permissions'], 'sysadm', None, None, None, None) and
       (not checkPermissions(request.session['permissions'], 'proadm', None, None, None, None) or owner_id != request.user.user_id)):
        return redirect('/memento')

    layer_id = request.session['selected_project_layer_id']
    response = requestAPI(request.user.username, "DELETE", 'layers/' + str(layer_id))
    response = requestAPI(request.user.username, "GET", 'comments/bylayer_id/' + str(layer_id))
    if (response.status_code != 404):
        comments_data = response.json()
        for curr_comment in comments_data['comments']:
            response = requestAPI(request.user.username, "DELETE", 'comments/' + str(curr_comment['comment_id']))

    next_actions = []
    next_actions.append({ 'url': reverse(views.home), 'text': 'Go back to the main menu'})
    next_actions.append({ 'url': reverse('edit_annotation') +
                                 '?annotation_id=' + str(annotation_id),
                          'text': 'Keep editing the annotation'})
    next_actions.append({ 'url': reverse('edit_category') +
                                 '?category_id=' + str(category_id),
                          'text': 'Keep editing the category'})
    next_actions.append({ 'url': reverse('edit_project') +
                                '?project_id=' + str(project_id),
                          'text': 'Keep editing the project'})
    return return_message(request, 'Layer removed', [], 'ok', next_actions)


@login_required
def update_share_annotation(request):
    project_id = request.session['selected_project_id']
    owner_id = request.session['selected_project_owner']
    if (not checkPermissions(request.session['permissions'], 'sysadm', None, None, None, None) and
       (not checkPermissions(request.session['permissions'], 'proadm', None, None, None, None) or owner_id != request.user.user_id)):
        return redirect('/memento')

    annotation_id = request.session['selected_project_annotation_id']
    response = requestAPI(request.user.username, "GET", 'annotations/' + str(annotation_id))
    if (response.status_code == 404):
        next_actions = []
        next_actions.append({ 'url': reverse(views.home), 'text': 'Go back to the main menu'})
        return return_message(request, 'Annotation not found', [], 'nok', next_actions)

    annotations_data = response.json()
    shared = ''
    if (annotations_data['annotation']['shared'] == ''):
        shared = get_random_string(50)
    response = requestAPI(request.user.username, "PUT", 'annotations/' + str(annotation_id), payload={'name': annotations_data['annotation']['name'], 'status': annotations_data['annotation']['status'],
                                    'shared': shared, 'image_id': annotations_data['annotation']['image_id'],
                                    'project_id': annotations_data['annotation']['project_id'], 'category_id': annotations_data['annotation']['category_id'],
                                    'owner_id': annotations_data['annotation']['owner_id']})

    return redirect('memento/edit_annotation?annotation_id=' + str(annotation_id))


@login_required
def delete_annotation_labels(request):
    project_id = request.session['selected_project_id']
    owner_id = request.session['selected_project_owner']
    if (not checkPermissions(request.session['permissions'], 'sysadm', None, None, None, None) and
       (not checkPermissions(request.session['permissions'], 'proadm', None, None, None, None) or owner_id != request.user.user_id)):
        return redirect('/memento')

    annotation_id = request.session['selected_project_annotation_id']
    response = requestAPI(request.user.username, "GET", 'annotations/' + str(annotation_id))
    if (response.status_code == 404):
        next_actions = []
        next_actions.append({ 'url': reverse(views.home), 'text': 'Go back to the main menu'})
        return return_message(request, 'Annotation not found', [], 'nok', next_actions)

    annotations_data = response.json()
    response = requestAPI(request.user.username, "PUT", 'annotations/' + str(annotation_id), payload={'name': annotations_data['annotation']['name'], 'status': 'N', 'shared': annotations_data['annotation']['shared'],
                                    'image_id': annotations_data['annotation']['image_id'], 'project_id': annotations_data['annotation']['project_id'],
                                    'category_id': annotations_data['annotation']['category_id'],
                                    'owner_id': annotations_data['annotation']['owner_id']})

    response = requestAPI(request.user.username, "DELETE", 'annotations_labels/byfilter/' + str(annotation_id) + '/0')

    return redirect('memento/edit_annotation?annotation_id=' + str(annotation_id))


def viewer(request):
    project_id = int(request.GET.get('project_id', None))
    shared = request.GET.get('share', '')
    if (shared == ''):
        if not request.user.is_authenticated:
            return render(request, 'memento/login.html')
    else:
        if not request.user.is_authenticated:
            request.session['permissions'] = []
        category_id = int(request.GET.get('category_id', None))
        annotation_id = int(request.GET.get('annotation_id', None))

    request.session['selected_share'] = None
    response = requestAPI(request.user.username, "GET", 'projects/' + str(project_id))
    if (response.status_code == 404):
        return redirect('/memento')
    project_data = response.json()
    request.session['selected_project_id'] = project_id
    request.session['selected_project_owner'] = project_data['project']['owner_id']
    context = {'project_name': project_data['project']['name']}

    has_to_annotate = -1
    request.session['has_labels'] = True
    response = requestAPI(request.user.username, "GET", 'labels/byproject_id/' + str(project_id))
    if (response.status_code == 404):
        request.session['has_labels'] = False
        has_to_annotate = 0

    request.session['has_classifications'] = True
    response = requestAPI(request.user.username, "GET", 'classifications/byproject_id/' + str(project_id))
    if (response.status_code == 404):
        request.session['has_classifications'] = False

    request.session['selected_project_settings'] = ""
    clastype = 'i'
    if (project_data['project']['settings']):
        request.session['selected_project_settings'] = project_data['project']['settings']
        pro_settings = dict(item.split(":") for item in project_data['project']['settings'].split(","))
        if ('expandclassification' in pro_settings):
            context['expandclassification'] = pro_settings['expandclassification']
        if ('expandannotation' in pro_settings):
            context['expandannotation'] = pro_settings['expandannotation']
        if ('fastannotation' in pro_settings):
            context['fastannotation'] = pro_settings['fastannotation']
        if ('fastgroup' in pro_settings):
            context['fastgroup'] = pro_settings['fastgroup']
        if ('annotationexclusive' in pro_settings):
            context['annotationexclusive'] = pro_settings['annotationexclusive']
        if ('expandlayer' in pro_settings):
            context['expandlayer'] = pro_settings['expandlayer']
        if ('expandcomment' in pro_settings):
            context['expandcomment'] = pro_settings['expandcomment']
        if ('darkmode' in pro_settings):
            context['darkmode'] = pro_settings['darkmode']
        if ('clastype' in pro_settings):
            clastype = pro_settings['clastype']
        if ('visibilityexclusive' in pro_settings):
            context['visibilityexclusive'] = pro_settings['visibilityexclusive']
        if ('visibilitygroupexclusive' in pro_settings):
            context['visibilitygroupexclusive'] = pro_settings['visibilitygroupexclusive']
    context['clastype'] = clastype

    allowed_images = []

    if (shared != ''):
        has_to_annotate = 0
        response_categories = requestAPI(request.user.username, "GET", 'categories/' + str(category_id))
        if (response_categories.status_code == 404):
            return redirect('/memento')
        categories_data = response_categories.json()['category']
        response_annotations = requestAPI(request.user.username, "GET", 'annotations/' + str(annotation_id))
        if (response_categories.status_code == 404):
            return redirect('/memento')
        annotations_data = response_annotations.json()['annotation']
        if (annotations_data['shared'] != shared):
            return redirect('/memento')
        has_comments = False
        response_layers = requestAPI(request.user.username, "GET", 'layers/byannotation_id/' + str(annotations_data['annotation_id']))
        if (response_layers.status_code != 404):
            layer_data = response_layers.json()
            for curr_layer in layer_data['layers']:
                allowed_images.append(curr_layer['image_id'])
                response_comments = requestAPI(request.user.username, "GET", 'comments/bylayer_id/' + str(curr_layer['layer_id']))
                if (response_comments.status_code != 404):
                    has_comments = True

        annotations_list = []
        annotations_list.append({'id': annotations_data['annotation_id'], 'name': annotations_data['name'], 'image_id': annotations_data['image_id'],
                                 'status': annotations_data['status'], 'shared': annotations_data['shared'], 'has_comments': has_comments})

        categories_list = []
        categories_list.append({'id': categories_data['category_id'], 'name': categories_data['name']})
        request.session['allowed_categories'] = categories_list
        request.session['allowed_annotations'] = annotations_list
        context['selected_category_id'] = category_id

        request.session['selected_project_category_id'] = category_id
        request.session['selected_project_annotation_id'] = annotation_id
        request.session['selected_share'] = shared
    else:
        is_sysadm = any('sysadm' in permission['type'] for permission in request.session['permissions'])
        is_proown = (request.user.user_id == project_data['project']['owner_id'])
        is_propar = False
        for permission in request.session['permissions']:
            if ((permission['type'] == 'propar' or permission['type'] == 'provie') and permission['type_id'] == project_id):
                is_propar = True
                break

        response_categories = requestAPI(request.user.username, "GET", 'categories/byproject_id/' + str(project_id))
        if (response_categories.status_code != 404):
            categories_data = response_categories.json()
            categories_list = []
            for curr_category in categories_data['categories']:
                allowed = False
                if (is_sysadm or is_proown or is_propar):
                    allowed = True
                    if (has_to_annotate < 0):
                        response_next_annotations = requestAPI(request.user.username, "GET", 'annotations/next/' + str(project_id) + '/0')
                        if (response_next_annotations.status_code == 404):
                            has_to_annotate = 0
                        else:
                            has_to_annotate = 1
                else:
                    for permission in request.session['permissions']:
                        if ((permission['type'] == 'catpar' or permission['type'] == 'catvie') and permission['type_id'] == curr_category['category_id']):
                            allowed = True
                            if (has_to_annotate <= 0):
                                response_next_annotations = requestAPI(request.user.username, "GET", 'annotations/next/' + str(project_id) + '/' + str(curr_category['category_id']))
                                if (response_next_annotations.status_code == 404):
                                    has_to_annotate = 0
                                else:
                                    has_to_annotate = 1
                            break

                    if (not allowed):
                        for permission in request.session['permissions']:
                            if (permission['type'] == 'annpar' or permission['type'] == 'annvie'):
                                response_annotations = requestAPI(request.user.username, "GET", 'annotations/' + str(permission['type_id']))
                                if (response_annotations.status_code != 404):
                                    annotation_data = response_annotations.json()
                                    if (annotation_data['annotation']['category_id'] == curr_category['category_id']):
                                        allowed = True
                                        if (has_to_annotate <= 0 and annotation_data['annotation']['status'] == 'N'):
                                            has_to_annotate = 1
                                        break

                if (allowed):
                    classification = ''
                    response_categories_classifications = requestAPI(request.user.username, "GET", 'categories_classifications/byfilter/' + str(curr_category['category_id']) + '/0')
                    if (response_categories_classifications.status_code != 404):
                        categories_classifications_data = response_categories_classifications.json()
                        for curr_cateclas in categories_classifications_data['categories_classifications']:
                            response_classification = requestAPI(request.user.username, "GET", 'classifications/' + str(curr_cateclas['classification_id']))
                            if (response_classification.status_code != 404):
                                classifications_data = response_classification.json()['classification']
                                if (classifications_data['type'] == 'M'):
                                    if (clastype == 'i'):
                                        classification = classifications_data['data'].split("#")[0]
                                    else:
                                        classification = classifications_data['data'].split("#")[1]

                    categories_list.append({'id': curr_category['category_id'], 'name': curr_category['name'], 'classification': classification})
            request.session['allowed_categories'] = categories_list
            context['selected_category_id'] = categories_list[0]['id']

    context['has_to_annotate'] = has_to_annotate
    request.session['allowed_images'] = list(set(allowed_images))

    return render(request, 'memento/viewer.html', context)


def viewer_limited(request):
    project_id = int(request.GET.get('project_id', None))
    shared = request.GET.get('share', '')
    if (shared == ''):
        if not request.user.is_authenticated:
            return render(request, 'memento/login.html')
    else:
        category_id = int(request.GET.get('category_id', None))
        annotation_id = int(request.GET.get('annotation_id', None))

    request.session['selected_share'] = None
    response = requestAPI(request.user.username, "GET", 'projects/' + str(project_id))
    if (response.status_code == 404):
        return redirect('/memento')
    project_data = response.json()
    request.session['selected_project_id'] = project_id
    request.session['selected_project_owner'] = project_data['project']['owner_id']
    context = {'project_name': project_data['project']['name']}

    allowed_images = []

    if (shared != ''):
        response_categories = requestAPI(request.user.username, "GET", 'categories/' + str(category_id))
        if (response_categories.status_code == 404):
            return redirect('/memento')
        categories_data = response_categories.json()['category']
        response_annotations = requestAPI(request.user.username, "GET", 'annotations/' + str(annotation_id))
        if (response_categories.status_code == 404):
            return redirect('/memento')
        annotations_data = response_annotations.json()['annotation']
        if (annotations_data['shared'] != shared):
            return redirect('/memento')

        annotations_list = []
        annotations_list.append({'id': annotations_data['annotation_id'], 'name': annotations_data['name'], 'image_id': annotations_data['image_id'],
                                 'status': annotations_data['status'], 'shared': annotations_data['shared'], 'has_comments': False})
        allowed_images.append(annotations_data['image_id'])

        categories_list = []
        categories_list.append({'id': categories_data['category_id'], 'name': categories_data['name']})
        request.session['allowed_categories'] = categories_list
        request.session['allowed_annotations'] = annotations_list
        context['selected_category_id'] = category_id

        request.session['selected_project_category_id'] = category_id
        request.session['selected_project_annotation_id'] = annotation_id
        request.session['selected_share'] = shared
    else:
        is_sysadm = any('sysadm' in permission['type'] for permission in request.session['permissions'])
        is_proown = (request.user.user_id == project_data['project']['owner_id'])
        is_propar = False
        for permission in request.session['permissions']:
            if ((permission['type'] == 'propar' or permission['type'] == 'provie') and permission['type_id'] == project_id):
                is_propar = True
                break

        response_categories = requestAPI(request.user.username, "GET", 'categories/byproject_id/' + str(project_id))
        if (response_categories.status_code != 404):
            categories_data = response_categories.json()
            categories_list = []
            for curr_category in categories_data['categories']:
                allowed = False
                if (is_sysadm or is_proown or is_propar):
                    allowed = True
                else:
                    for permission in request.session['permissions']:
                        if ((permission['type'] == 'catpar' or permission['type'] == 'catvie') and permission['type_id'] == curr_category['category_id']):
                            allowed = True
                            break

                    if (not allowed):
                        for permission in request.session['permissions']:
                            if (permission['type'] == 'annpar' or permission['type'] == 'annvie'):
                                response_annotations = requestAPI(request.user.username, "GET", 'annotations/' + str(permission['type_id']))
                                if (response_annotations.status_code != 404):
                                    annotation_data = response_annotations.json()
                                    if (annotation_data['annotation']['category_id'] == curr_category['category_id']):
                                        allowed = True
                                        break

                if (allowed):
                    categories_list.append({'id': curr_category['category_id'], 'name': curr_category['name']})
            request.session['allowed_categories'] = categories_list
            request.session['selected_project_category_id'] = categories_list[0]['id']

    request.session['allowed_images'] = list(set(allowed_images))

    return render(request, 'memento/viewer_limited.html', context)


@login_required
def image_grid(request):
    project_id = request.session['selected_project_id']
    category_id = int(request.GET.get('category_id', None))
    response = requestAPI(request.user.username, "GET", 'projects/' + str(project_id))
    if (response.status_code == 404):
        return redirect('/memento')
    project_data = response.json()
    response = requestAPI(request.user.username, "GET", 'categories/' + str(category_id))
    if (response.status_code == 404):
        return HttpResponse(status=404)
    context = {}
    for category in request.session['allowed_categories']:
        if category['id'] == category_id:
            allowed_images = []
            annotations_list = []
            response_annotations = requestAPI(request.user.username, "GET", 'annotations/bycategory_id/' + str(category_id))
            if (response_annotations.status_code != 404):
                annotations_data = response_annotations.json()

                allowed = False
                is_sysadm = any('sysadm' in permission['type'] for permission in request.session['permissions'])
                is_proown = (request.user.user_id == project_data['project']['owner_id'])
                is_propar = False
                for permission in request.session['permissions']:
                    if ((permission['type'] == 'propar' or permission['type'] == 'provie') and permission['type_id'] == project_id):
                        is_propar = True
                        break
                if (is_sysadm or is_proown or is_propar):
                    allowed = True
                if (not allowed):
                    for permission in request.session['permissions']:
                        if ((permission['type'] == 'catpar' or permission['type'] == 'catvie') and permission['type_id'] == category['id']):
                            allowed = True
                            break

                for curr_annotation in annotations_data['annotations']:
                    allowed_annotation = allowed
                    if (not allowed_annotation):
                        for permission in request.session['permissions']:
                            if ((permission['type'] == 'annpar' or permission['type'] == 'annvie') and permission['type_id'] == curr_annotation['annotation_id']):
                                allowed_annotation = True
                                break

                    if (allowed_annotation):
                        has_comments = False
                        response_layers = requestAPI(request.user.username, "GET", 'layers/byannotation_id/' + str(curr_annotation['annotation_id']))
                        if (response_layers.status_code != 404):
                            layer_data = response_layers.json()
                            for curr_layer in layer_data['layers']:
                                allowed_images.append(curr_layer['image_id'])
                                response_comments = requestAPI(request.user.username, "GET", 'comments/bylayer_id/' + str(curr_layer['layer_id']))
                                if (response_comments.status_code != 404):
                                    has_comments = True

                        annotations_list.append({'id': curr_annotation['annotation_id'], 'name': curr_annotation['name'],
                                                 'image_id': curr_annotation['image_id'], 'status': curr_annotation['status'],
                                                 'shared': curr_annotation['shared'], 'has_comments': has_comments})

            context['annotations'] = annotations_list
            request.session['allowed_annotations'] = annotations_list

            category_data = response.json()
            if (category_data['category']['settings']):
                cat_settings = dict(item.split(":") for item in category_data['category']['settings'].split(","))
                if ('forcerow' in cat_settings):
                    context['forcerow'] = int(cat_settings['forcerow'])
                if ('names' in cat_settings):
                    context['names'] = cat_settings['names']
                if ('darkmode' in cat_settings):
                    context['darkmode'] = cat_settings['darkmode']
                break

            request.session['allowed_images'] = list(set(allowed_images))

    if not 'annotations' in context or not context['annotations']:
        next_actions = []
        next_actions.append({ 'url': reverse(views.home), 'text': 'Go back to the main menu'})
        return return_message_content(request, 'No annotations found', [], 'nok', next_actions)

    request.session['selected_project_category_id'] = category_id

    return render(request, 'memento/image_grid.html', context)


@login_required
def annotations_limited(request):
    project_id = request.session['selected_project_id']
    category_id = int(request.GET.get('category_id', None))
    response = requestAPI(request.user.username, "GET", 'projects/' + str(project_id))
    if (response.status_code == 404):
        return redirect('/memento')
    project_data = response.json()
    response = requestAPI(request.user.username, "GET", 'categories/' + str(category_id))
    if (response.status_code == 404):
        return HttpResponse(status=404)
    annotations_list = []
    for category in request.session['allowed_categories']:
        if category['id'] == category_id:
            allowed_images = []
            response_annotations = requestAPI(request.user.username, "GET", 'annotations/bycategory_id/' + str(category_id))
            if (response_annotations.status_code != 404):
                annotations_data = response_annotations.json()

                allowed = False
                is_sysadm = any('sysadm' in permission['type'] for permission in request.session['permissions'])
                is_proown = (request.user.user_id == project_data['project']['owner_id'])
                is_propar = False
                for permission in request.session['permissions']:
                    if ((permission['type'] == 'propar' or permission['type'] == 'provie') and permission['type_id'] == project_id):
                        is_propar = True
                        break
                if (is_sysadm or is_proown or is_propar):
                    allowed = True
                if (not allowed):
                    for permission in request.session['permissions']:
                        if ((permission['type'] == 'catpar' or permission['type'] == 'catvie') and permission['type_id'] == category_id):
                            allowed = True
                            break

                for curr_annotation in annotations_data['annotations']:
                    allowed_annotation = allowed
                    if (not allowed_annotation):
                        for permission in request.session['permissions']:
                            if ((permission['type'] == 'annpar' or permission['type'] == 'annvie') and permission['type_id'] == curr_annotation['annotation_id']):
                                allowed_annotation = True
                                break

                    if (allowed_annotation):
                        allowed_images.append(curr_annotation['image_id'])
                        annotations_list.append(str(curr_annotation['annotation_id']) + ":" + curr_annotation['name'] + ":" + str(curr_annotation['image_id']))

            request.session['allowed_images'] = list(set(allowed_images))

    request.session['selected_project_category_id'] = category_id

    return HttpResponse('###'.join(annotations_list))


def image_editor(request):
    project_id = request.session['selected_project_id']
    annotation_id = int(request.GET.get('annotation_id', None))

    shared = request.session.get('selected_share', None)
    if (not shared):
        if not request.user.is_authenticated:
            return HttpResponse(status=404)
    else:
        if annotation_id != request.session['selected_project_annotation_id']:
            return HttpResponse(status=404)

    response = requestAPI(request.user.username, "GET", 'annotations/' + str(annotation_id))
    if (response.status_code == 404):
        return HttpResponse(status=404)
    context = {}
    annotation_data = response.json()['annotation']
    category_id = annotation_data['category_id']
    image_id = annotation_data['image_id']
    for curr_annotation in request.session['allowed_annotations']:
        if (curr_annotation['id'] == annotation_id):
            context['image_id'] = curr_annotation['image_id']
            context['sharedURL'] = ''
            if (curr_annotation['shared'] != ''):
                context['sharedURL'] = (request.build_absolute_uri('viewer') + '?project_id=' + str(project_id) + '&category_id=' + str(category_id) +
                                                                                    '&annotation_id=' + str(annotation_id) + '&share=' + curr_annotation['shared'])
                break
    if not 'image_id' in context:
        return HttpResponse(status=404)

    response = requestAPI(request.user.username, "GET", 'images/' + str(context['image_id']))
    if (response.status_code == 404):
        return HttpResponse(status=404)
    image_data = response.json()['image']
    context['image_uri'] = image_data['uri']
    context['image_type'] = image_data['type']
    context['image_resolution'] = image_data['resolution']

    response = requestAPI(request.user.username, "GET", 'layers/byannotation_id/' + str(annotation_id))
    if (response.status_code == 404):
        return HttpResponse(status=404)

    layers_data = response.json()['layers']
    layer_id = layers_data[0]['layer_id']
    context['layer_id'] = layer_id

    group_layers = []
    layers_list = []
    for layer in layers_data:
        if (layer_id != layer['layer_id']):
            layer_image_id = 0
            layer_image_uri = ''
            layer_image_type = ''
            layer_image_resolution = ''
            if (layer['image_id'] > 0):
                response = requestAPI(request.user.username, "GET", 'images/' + str(layer['image_id']))
                if (response.status_code == 404):
                    return HttpResponse(status=404)
                image_data = response.json()['image']
                layer_image_uri = image_data['uri']
                layer_image_type = image_data['type']
                layer_image_resolution = image_data['resolution']
            layers_list.append({'id': layer['layer_id'], 'data': layer['data'], 'image_id': layer['image_id'], 'image_uri': layer_image_uri, 'image_type': layer_image_type, 'image_resolution': layer_image_resolution})
            if (layer['parent_id'] == 0 and layer['data'] == ''):
                group_layers.append(layer['layer_id'])

    context['layers'] = layers_list
    context['group_layers'] = group_layers
    context['has_layers'] = True

    context['has_comments'] = True

    request.session['selected_project_annotation_id'] = annotation_id
    request.session['selected_project_layer_id'] = layer_id

    return render(request, 'memento/image_editor.html', context)


def layer_editor(request):
    project_id = request.session['selected_project_id']
    annotation_id = int(request.GET.get('annotation_id', None))
    layer_id = int(request.GET.get('layer_id', None))

    shared = request.session.get('selected_share', None)
    can_be_owner = False
    if (not shared):
        if not request.user.is_authenticated:
            return HttpResponse(status=404)
        is_sysadm = any('sysadm' in permission['type'] for permission in request.session['permissions'])
        is_proown = request.session['selected_project_owner'] == request.user.user_id
        can_be_owner = is_sysadm or is_proown
    else:
        if annotation_id != request.session['selected_project_annotation_id']:
            return HttpResponse(status=404)

    response = requestAPI(request.user.username, "GET", 'layers/byannotation_id/' + str(annotation_id))
    if (response.status_code == 404):
        return HttpResponse(status=404)

    layers_data = response.json()['layers']
    if layer_id == 0:
        layer_id = layers_data[0]['layer_id']

    context = {}
    layers_list = []
    group_layers = []
    for layer in layers_data:
        layer_info = {}
        layer_info['id'] = layer['layer_id']
        layer_info['name'] = layer['name']
        layer_info['data'] = layer['data']
        layer_info['parent_id'] = layer['parent_id']
        layer_info['is_owner'] = True
        if (shared or (not can_be_owner and layer['owner_id'] != request.user.user_id)):
            layer_info['is_owner'] = False
        response = requestAPI(request.user.username, "GET", 'comments/bylayer_id/' + str(layer['layer_id']))
        if (response.status_code != 404):
            layer_info['num_comments'] = len(response.json()['comments'])
        else:
            layer_info['num_comments'] = 0
        if (layer['image_id'] > 0):
            layer_info['active'] = True
        else:
            layer_info['active'] = False
            if (layer['parent_id'] == 0 and layer['data'] == ''):
                group_layers.append(layer['layer_id'])
        layers_list.append(layer_info)

    context['layers'] = layers_list
    context['group_layers'] = group_layers

    request.session['selected_project_annotation_id'] = annotation_id
    request.session['selected_project_layer_id'] = layer_id

    return render(request, 'memento/layer_editor.html', context)


def annotation_editor(request):
    project_id = request.session['selected_project_id']
    annotation_id = int(request.GET.get('annotation_id', None))

    shared = request.session.get('selected_share', None)
    if (not shared):
        if not request.user.is_authenticated:
            return HttpResponse(status=404)
    else:
        if annotation_id != request.session['selected_project_annotation_id']:
            return HttpResponse(status=404)

    response = requestAPI(request.user.username, "GET", 'annotations/' + str(annotation_id))
    if (response.status_code == 404):
        return HttpResponse(status=404)
    annotation_data = response.json()['annotation']
    category_id = annotation_data['category_id']
    status = annotation_data['status']

    context = {}
    label_list = []
    for curr_annotation in request.session['allowed_annotations']:
        if (curr_annotation['id'] == annotation_id):
            response = requestAPI(request.user.username, "GET", 'labels/byproject_id/' + str(project_id))
            if (response.status_code == 404):
                return HttpResponse('')

            labels_data = response.json()['labels']
            for curr_label in labels_data:
                label_list.append({'id': curr_label['label_id'], 'name': curr_label['name'], 'active' : False})

                response = requestAPI(request.user.username, "GET", 'annotations_labels/byfilter/' + str(annotation_id) + '/0')
                annotations_labels_data = response.json()['annotations_labels']
                for curr_annotation_label in annotations_labels_data:
                    for curr_label in label_list:
                        if (curr_label['id'] == curr_annotation_label['label_id']):
                            curr_label['active'] = True

            context['labels'] = label_list
            context['status'] = annotation_data['status']
            break

    if (request.session['selected_project_settings'] and request.session['selected_project_settings'] != ""):
        pro_settings = dict(item.split(":") for item in request.session['selected_project_settings'].split(","))
        if ('fastannotation' in pro_settings):
            context['fastannotation'] = pro_settings['fastannotation']
        if ('annotationexclusive' in pro_settings):
            context['annotationexclusive'] = pro_settings['annotationexclusive']

    request.session['selected_project_annotation_id'] = annotation_id

    return render(request, 'memento/annotation_editor.html', context)


def classification_editor(request):
    project_id = request.session['selected_project_id']
    category_id = int(request.GET.get('category_id', None))

    context = {}

    context['classification_active'] = ''
    response_cateclas = requestAPI(request.user.username, "GET", 'categories_classifications/byfilter/' + str(category_id) + '/0')
    if (response_cateclas.status_code != 404):
        cateclas_data = response_cateclas.json()
        for curr_cateclas in cateclas_data['categories_classifications']:
            response_classification = requestAPI(request.user.username, "GET", 'classifications/' + str(curr_cateclas['classification_id']))
            if (response_classification.status_code != 404):
                classification_data = response_classification.json()['classification']
                if (classification_data['type'] == 'M'):
                    context['classification_active'] = classification_data['classification_id']

    classifications_list = []
    response = requestAPI(request.user.username, "GET", 'classifications/byproject_id/' + str(project_id))
    if (response.status_code == 404):
        return HttpResponse('')

    classifications_data = response.json()['classifications']
    for curr_classification in classifications_data:
        classifications_list.append({'id': curr_classification['classification_id'], 'name': curr_classification['name'],
                                     'icon': curr_classification['data'].split('#')[0], 'letter': curr_classification['data'].split('#')[1]})

    context['classifications'] = classifications_list

    request.session['selected_project_category_id'] = category_id

    return render(request, 'memento/classification_editor.html', context)


def next_annotation(request):
    project_id = request.session['selected_project_id']

    response = requestAPI(request.user.username, "GET", 'projects/' + str(project_id))
    if (response.status_code == 404):
        return redirect('/memento')
    project_data = response.json()

    response = requestAPI(request.user.username, "GET", 'labels/byproject_id/' + str(project_id))
    if (response.status_code == 404):
        return HttpResponse('')

    next_annotations = []
    is_sysadm = any('sysadm' in permission['type'] for permission in request.session['permissions'])
    is_proown = (request.user.user_id == project_data['project']['owner_id'])
    is_propar = False
    for permission in request.session['permissions']:
        if (permission['type'] == 'propar' and permission['type_id'] == project_id):
            is_propar = True
            break

    response_next_annotations = requestAPI(request.user.username, "GET", 'annotations/next/' + str(project_id) + '/0')
    if (response_next_annotations.status_code == 404):
        return HttpResponse('')
    else:
        next_annotation_data = response_next_annotations.json()['next']
        for curr_next_annotation in next_annotation_data:
            if (is_sysadm or is_proown or is_propar):
                next_annotations.append(str(curr_next_annotation['category_id']) + '-' + str(curr_next_annotation['annotation_id']))
            else:
                added = False
                for permission in request.session['permissions']:
                    if (permission['type'] == 'catpar' and permission['type_id'] == curr_next_annotation['category_id']):
                        next_annotations.append(str(curr_next_annotation['category_id']) + '-' + str(curr_next_annotation['annotation_id']))
                        added = True
                        break

                if (not added):
                    for permission in request.session['permissions']:
                        if (permission['type'] == 'annpar' and permission['type_id'] == curr_next_annotation['annotation_id']):
                            next_annotations.append(str(curr_next_annotation['category_id']) + '-' + str(curr_next_annotation['annotation_id']))
                            break

    return HttpResponse(','.join(next_annotations))


def comment_editor(request):
    project_id = request.session['selected_project_id']
    annotation_id = int(request.GET.get('annotation_id', None))

    shared = request.session.get('selected_share', None)
    can_be_owner = False
    if (not shared):
        if not request.user.is_authenticated:
            return HttpResponse(status=404)
        is_sysadm = any('sysadm' in permission['type'] for permission in request.session['permissions'])
        is_proown = request.session['selected_project_owner'] == request.user.user_id
        can_be_owner = is_sysadm or is_proown
    else:
        if annotation_id != request.session['selected_project_annotation_id']:
            return HttpResponse(status=404)

    layer_id = int(request.GET.get('layer_id', None))
    layer_data = ''
    if layer_id == 0:
        response = requestAPI(request.user.username, "GET", 'layers/byannotation_id/' + str(annotation_id))
        if (response.status_code == 404):
            return HttpResponse(status=404)
        layer_data = response.json()['layers'][0]
    else:
        response = requestAPI(request.user.username, "GET", 'layers/' + str(layer_id))
        if (response.status_code == 404):
            return HttpResponse(status=404)
        layer_data = response.json()['layer']

    layer_id = layer_data['layer_id']
    context = {'comments': []}
    comments_list = []
    response = requestAPI(request.user.username, "GET", 'comments/bylayer_id/' + str(layer_id))
    if (response.status_code != 404):
        comments_data = response.json()['comments']
        for comment in comments_data:
            if (shared or (not can_be_owner and comment['owner_id'] != request.user.user_id)):
                comments_list.append({'id': comment['comment_id'], 'content': comment['content'], 'is_owner': False})
            else:
                comments_list.append({'id': comment['comment_id'], 'content': comment['content'], 'is_owner': True})

        context['comments'] = comments_list

    context['annotation_id'] = annotation_id

    request.session['selected_project_annotation_id'] = annotation_id
    request.session['selected_project_layer_id'] = layer_id

    return render(request, 'memento/comment_editor.html', context)


def submit_share_annotation(request):
    project_id = request.session['selected_project_id']
    category_id = request.session['selected_project_category_id']
    annotation_id = request.session['selected_project_annotation_id']

    if (not checkPermissions(request.session['permissions'], 'ann', 'par', project_id, category_id, annotation_id)):
        return HttpResponse('nok')

    shared = request.session.get('selected_share', None)
    if (not shared):
        if not request.user.is_authenticated:
            return HttpResponse('nok')

    response = requestAPI(request.user.username, "GET", 'annotations/' + str(annotation_id))
    if (response.status_code == 404):
        return HttpResponse('nok')

    annotations_data = response.json()
    shared = ''
    if (annotations_data['annotation']['shared'] == ''):
        shared = get_random_string(50)
    response = requestAPI(request.user.username, "PUT", 'annotations/' + str(annotation_id), payload={'name': annotations_data['annotation']['name'], 'status': annotations_data['annotation']['status'],
                                    'shared': shared, 'image_id': annotations_data['annotation']['image_id'],
                                    'project_id': annotations_data['annotation']['project_id'], 'category_id': annotations_data['annotation']['category_id'],
                                    'owner_id': annotations_data['annotation']['owner_id']})
    sharedURL = ''
    if (shared != ''):
        sharedURL = (request.build_absolute_uri('viewer') + '?project_id=' + str(project_id) + '&category_id=' + str(category_id) +
                                                                '&annotation_id=' + str(annotation_id) + '&share=' + shared)

    return HttpResponse(sharedURL)


def new_layer_viewer(request):
    project_id = request.session['selected_project_id']
    category_id = request.session['selected_project_category_id']
    annotation_id = request.session['selected_project_annotation_id']
    name = request.GET.get('name', None)

    owner_id = 0
    if request.user.is_authenticated:
        owner_id = request.user.user_id
    else:
        shared = request.session.get('selected_share', None)
        if (not shared):
            return HttpResponse('nok')

    if (not checkPermissions(request.session['permissions'], 'ann', 'par', project_id, category_id, annotation_id)):
        return HttpResponse('nok')

    response = requestAPI(request.user.username, "GET", 'layers/byannotation_id/' + str(annotation_id))
    if (response.status_code == 404):
        return HttpResponse('nok')
    layers_data = response.json()['layers']

    curr_sequence = (layers_data[len(layers_data) - 1]['sequence'] + 1)
    response = requestAPI(request.user.username, "POST", 'layers', payload={'name': name, 'data': '', 'image_id': 0, 'sequence': curr_sequence, 'parent_id': 0, 'annotation_id': annotation_id, 'owner_id' : owner_id})
    if (response.status_code != 201):
        return HttpResponse('nok')

    layer_id = response.json()['layer']['layer_id']
    return HttpResponse(str(layer_id))


def save_layer_viewer(request):
    project_id = request.session['selected_project_id']
    category_id = request.session['selected_project_category_id']
    annotation_id = request.session['selected_project_annotation_id']
    layer_id = request.POST.get("layer_id")
    data = request.POST.get("data")

    if (not checkPermissions(request.session['permissions'], 'ann', 'par', project_id, category_id, annotation_id)):
        return HttpResponse('nok')

    response = requestAPI(request.user.username, "GET", 'layers/' + str(layer_id))
    if (response.status_code == 404):
        return HttpResponse('nok')
    layer_data = response.json()['layer']

    shared = request.session.get('selected_share', None)
    if (not shared):
        if not request.user.is_authenticated:
            return HttpResponse('nok')
    else:
        if layer_data['annotation_id'] != request.session['selected_project_annotation_id']:
            return HttpResponse('nok')

    response = requestAPI(request.user.username, "PUT", 'layers/' + str(layer_id), payload={'name': layer_data['name'], 'data': data, 'image_id': 0, 'sequence': layer_data['sequence'], 'parent_id': layer_data['parent_id'],
                                     'annotation_id': layer_data['annotation_id'], 'owner_id' : layer_data['owner_id']})
    if (response.status_code != 201):
        return HttpResponse('nok')

    return HttpResponse(str(layer_id))


def delete_layer_viewer(request):
    project_id = request.session['selected_project_id']
    category_id = request.session['selected_project_category_id']
    annotation_id = request.session['selected_project_annotation_id']
    layer_id = int(request.GET.get('layer_id', None))

    shared = request.session.get('selected_share', None)
    if (not shared):
        if not request.user.is_authenticated:
            return HttpResponse('nok')

    if (not checkPermissions(request.session['permissions'], 'ann', 'par', project_id, category_id, annotation_id)):
        return HttpResponse('nok')

    response = requestAPI(request.user.username, "GET", 'layers/' + str(layer_id))
    if (response.status_code == 404):
        return HttpResponse('nok')
    layer_data = response.json()['layer']
    if (layer_data['sequence'] == 1 or layer_data['image_id'] > 0):
        return HttpResponse('nok')

    is_sysadm = any('sysadm' in permission['type'] for permission in request.session['permissions'])
    is_proown = request.session['selected_project_owner'] == request.user.user_id
    if (not is_sysadm and not is_proown and layer_data['owner_id'] != request.user.user_id):
        return HttpResponse('nok')

    response = requestAPI(request.user.username, "DELETE", 'layers/' + str(layer_id))
    response = requestAPI(request.user.username, "GET", 'comments/bylayer_id/' + str(layer_id))
    if (response.status_code != 404):
        comments_data = response.json()
        for curr_comment in comments_data['comments']:
            response = requestAPI(request.user.username, "DELETE", 'comments/' + str(curr_comment['comment_id']))

    return HttpResponse("ok")


def submit_annotation_labels(request):
    project_id = request.session['selected_project_id']
    category_id = request.session['selected_project_category_id']
    annotation_id = request.session['selected_project_annotation_id']
    labels = request.GET.get('labels', None)

    shared = request.session.get('selected_share', None)
    if (not shared):
        if not request.user.is_authenticated:
            return HttpResponse('nok')

    if (not checkPermissions(request.session['permissions'], 'ann', 'par', project_id, category_id, annotation_id)):
        return HttpResponse('nok')

    labels_list = []
    if (labels):
        labels_list = labels.split(",")

    response = requestAPI(request.user.username, "DELETE", 'annotations_labels/byfilter/' + str(annotation_id) + '/0')

    response = requestAPI(request.user.username, "GET", 'labels/byproject_id/' + str(project_id))
    if (response.status_code == 404):
        return HttpResponse('nok')

    project_labels_data = response.json()['labels']
    for curr_project_label in project_labels_data:
        if str(curr_project_label['label_id']) in labels_list:
            response = requestAPI(request.user.username, "POST", 'annotations_labels', payload={'annotation_id': annotation_id, 'label_id' : curr_project_label['label_id']})
            if (response.status_code != 201):
                return HttpResponse('nok')

    response = requestAPI(request.user.username, "GET", 'annotations/' + str(annotation_id))
    if (response.status_code == 404):
        return HttpResponse('nok')

    annotation_data = response.json()['annotation']
    response = requestAPI(request.user.username, "PUT", 'annotations/' + str(annotation_id), payload={'name': annotation_data['name'], 'status': 'S', 'shared': annotation_data['shared'], 'image_id': annotation_data['image_id'],
                         'project_id': annotation_data['project_id'], 'category_id': annotation_data['category_id'], 'owner_id': annotation_data['owner_id']})
    if (response.status_code != 201):
        return HttpResponse('nok')

    return HttpResponse('ok')


def submit_classification(request):
    project_id = request.session['selected_project_id']
    category_id = request.session['selected_project_category_id']
    classification_id = request.GET.get('classification_id', None)

    if (not checkPermissions(request.session['permissions'], 'cat', 'par', project_id, category_id, None)):
        return HttpResponse('nok')

    response = requestAPI(request.user.username, "DELETE", 'categories_classifications/byfilter/' + str(category_id) + '/0')

    response = requestAPI(request.user.username, "GET", 'classifications/byproject_id/' + str(project_id))
    if (response.status_code == 404):
        return HttpResponse('nok')

    project_classifications_data = response.json()['classifications']
    for curr_project_classification in project_classifications_data:
        if str(curr_project_classification['classification_id']) == classification_id:
            response = requestAPI(request.user.username, "POST", 'categories_classifications', payload={'category_id': category_id, 'classification_id' : curr_project_classification['classification_id']})
            if (response.status_code != 201):
                return HttpResponse('nok')

    return HttpResponse('ok')


def submit_comment(request):
    project_id = request.session['selected_project_id']
    category_id = request.session['selected_project_category_id']
    annotation_id = request.session['selected_project_annotation_id']
    layer_id = request.session['selected_project_layer_id']
    comment_id = int(request.GET.get('comment_id', None))
    content = unescape(request.GET.get('content', None))

    owner_id = 0
    if request.user.is_authenticated:
        owner_id = request.user.user_id
    else:
        shared = request.session.get('selected_share', None)
        if (not shared):
            return HttpResponse('nok')

    if (not checkPermissions(request.session['permissions'], 'ann', 'par', project_id, category_id, annotation_id)):
        return HttpResponse('nok')

    if (comment_id == 0):
        curr_sequence = 1
        response = requestAPI(request.user.username, "GET", 'comments/bylayer_id/' + str(layer_id))
        if (response.status_code != 404):
            comments_data = response.json()['comments']
            curr_sequence = (comments_data[len(comments_data) - 1]['sequence'] + 1)

        content = request.user.username + ': ' + content
        response = requestAPI(request.user.username, "POST", 'comments', payload={'content': content, 'sequence': curr_sequence, 'layer_id': layer_id, 'owner_id' : owner_id})
        if (response.status_code != 201):
            return HttpResponse('nok')

        comment_id = response.json()['comment']['comment_id']
    else:
        response = requestAPI(request.user.username, "GET", 'comments/' + str(comment_id))
        comment_data = response.json()['comment']
        is_sysadm = any('sysadm' in permission['type'] for permission in request.session['permissions'])
        is_proown = request.session['selected_project_owner'] == request.user.user_id
        if (not is_sysadm and not is_proown and comment_data['owner_id'] != request.user.user_id):
            return HttpResponse('nok')
        response = requestAPI(request.user.username, "PUT", 'comments/' + str(comment_id), payload={'content': content, 'sequence': comment_data['sequence'], 'layer_id': comment_data['layer_id'], 'owner_id' : owner_id})
        if (response.status_code != 201):
            return HttpResponse('nok')

    return HttpResponse(str(comment_id) + '###' + content)


@login_required
def delete_comment_viewer(request):
    is_sysadm = any('sysadm' in permission['type'] for permission in request.session['permissions'])
    is_proown = request.session['selected_project_owner'] == request.user.user_id
    project_id = request.session['selected_project_id']
    category_id = request.session['selected_project_category_id']
    annotation_id = request.session['selected_project_annotation_id']
    layer_id = request.session['selected_project_layer_id']
    comment_id = int(request.GET.get('comment_id', None))

    shared = request.session.get('selected_share', None)
    if (not shared):
        if not request.user.is_authenticated:
            return HttpResponse('nok')

    if (not checkPermissions(request.session['permissions'], 'ann', 'par', project_id, category_id, annotation_id)):
        return HttpResponse('nok')

    response = requestAPI(request.user.username, "GET", 'comments/' + str(comment_id))
    if (response.status_code == 404):
        return HttpResponse('nok')

    comment_data = response.json()['comment']
    if (not is_sysadm and not is_proown and comment_data['owner_id'] != request.user.user_id):
        return HttpResponse('nok')

    response = requestAPI(request.user.username, "DELETE", 'comments/' + str(comment_id))
    return HttpResponse("ok")


def serve_image(request, id, options):
    if ('allowed_images' in request.session and id in request.session['allowed_images']):
        response = requestAPI(request.user.username, "GET", 'images/' + str(id))
        if (response.status_code != 404):
            image_data = response.json()['image']
            if (image_data['type'] == 'E'):
                response = HttpResponse(status=200)
                response['Content-Type'] = ''
                response['X-Accel-Redirect'] = '/memento/static/images/remote_image.png'
                return response

            image_type = '0'
            sub_filename = 'none'
            if 'thumb' in options:
                image_type = '1'
            elif 'subfile' in options:
                image_type = '0'
                sub_filename = options.replace('subfile', '') + image_data['uri'][image_data['uri'].index("."):]
            response = requestAPI(request.user.username, "GET", 'images/geturl/' + str(id) + '/' + image_type + '/' + sub_filename)
            if (response.status_code == 200):
                redirect_url = HttpResponse(status=302)
                redirect_url['Location'] = response.json()['url']
                return redirect_url

    return HttpResponse(status=404)


def get_random_string(length):
    letters = string.ascii_lowercase
    return ''.join(random.choice(letters) for i in range(length))
