import json
import os
import requests
from hashlib import sha256
from PIL import Image


REST_base_url = 'https://ell-core.stanford.edu/memento-api/'
cr_username = "username"
cr_password = "password"
auth = {'x-access-token': ""}


def login(input_username=None, input_password=None):
    global cr_username
    global cr_password
    global auth
    if input_username and input_password:
        cr_username = input_username
        cr_password = input_password

    response = requests.post(url=REST_base_url + 'login', headers={'username': cr_username, 'password': sha256(cr_password.encode('utf-8')).hexdigest()})
    if response.status_code != 200:
        return -1

    token = json.loads(response.text)
    auth = {'x-access-token': token['token']}
    return 0


def get_user_id(username):
    response = requests.get(REST_base_url + 'users/byusername/' + username, headers=auth)
    if response.status_code == 404:
        return -1

    return response.json()['user']['user_id']


def new_project(user_id, name, settings):
    response = requests.post(REST_base_url + 'projects', json={'name': name, 'owner_id': user_id, 'settings': settings}, headers=auth)
    if response.status_code != 201:
        return -1

    return response.json()['project']['project_id']


def delete_project(user_id, project_id):
    response = requests.get(REST_base_url + 'projects/' + str(project_id), headers=auth)
    if response.status_code == 404 or response.json()['project']['owner_id'] != user_id:
        return -1

    response = requests.delete(REST_base_url + 'projects/' + str(project_id), headers=auth)
    response = requests.delete(REST_base_url + 'permissions/byfilter/0/propar/' + str(project_id), headers=auth)

    response = requests.get(REST_base_url + 'categories/byproject_id/' + str(project_id), headers=auth)
    if response.status_code != 404:
        categories_data = response.json()
        for curr_category in categories_data['categories']:
            response = requests.delete(REST_base_url + 'categories/' + str(curr_category['category_id']), headers=auth)
            response = requests.delete(REST_base_url + 'permissions/byfilter/0/catpar/' + str(curr_category['category_id']), headers=auth)

    response = requests.get(REST_base_url + 'classifications/byproject_id/' + str(project_id), headers=auth)
    if response.status_code != 404:
        classifications_data = response.json()
        for curr_classification in classifications_data['classifications']:
            response = requests.delete(REST_base_url + 'classifications/' + str(curr_classification['classification_id']), headers=auth)
            response = requests.delete(REST_base_url + 'categories_classifications/byfilter/0/' + str(curr_classification['classification_id']), headers=auth)

    response = requests.get(REST_base_url + 'images/byproject_id/' + str(project_id), headers=auth)
    if response.status_code != 404:
        images_data = response.json()
        for curr_image in images_data['images']:
            response = requests.delete(REST_base_url + 'images/' + str(curr_image['image_id']), headers=auth)

    response = requests.get(REST_base_url + 'labels/byproject_id/' + str(project_id), headers=auth)
    if response.status_code != 404:
        labels_data = response.json()
        for curr_label in labels_data['labels']:
            response = requests.delete(REST_base_url + 'labels/' + str(curr_label['label_id']), headers=auth)
            response = requests.delete(REST_base_url + 'annotations_labels/byfilter/0/' + str(curr_label['label_id']), headers=auth)

    response = requests.get(REST_base_url + 'annotations/byproject_id/' + str(project_id), headers=auth)
    if response.status_code != 404:
        annotations_data = response.json()
        for curr_annotation in annotations_data['annotations']:
            response = requests.delete(REST_base_url + 'annotations/' + str(curr_annotation['annotation_id']), headers=auth)
            response = requests.delete(REST_base_url + 'permissions/byfilter/0/annpar/' + str(curr_annotation['annotation_id']), headers=auth)
            response = requests.delete(REST_base_url + 'annotations_labels/byfilter/' + str(curr_annotation['annotation_id']) + '/0', headers=auth)

            response = requests.get(REST_base_url + 'layers/byannotation_id/' + str(curr_annotation['annotation_id']), headers=auth)
            if response.status_code != 404:
                layers_data = response.json()
                for curr_layer in layers_data['layers']:
                    response = requests.delete(REST_base_url + 'layers/' + str(curr_layer['layer_id']), headers=auth)
                    response = requests.get(REST_base_url + 'comments/bylayer_id/' + str(curr_layer['layer_id']), headers=auth)
                    if response.status_code != 404:
                        comments_data = response.json()
                        for curr_comment in comments_data['comments']:
                            response = requests.delete(REST_base_url + 'comments/' + str(curr_comment['comment_id']), headers=auth)

    return 0


def upload_image(user_id, project_id, filepath, im_format, name, im_type, url):
    response = requests.get(REST_base_url + 'projects/' + str(project_id), headers=auth)
    if response.status_code == 404 or response.json()['project']['owner_id'] != user_id:
        return -1

    if im_type == 'E':
        response = requests.post(REST_base_url + 'images',
                                 json={'filepath': '', 'format': 0, 'name': name, 'uri': url, 'type': 'E', 'project_id': project_id, 'owner_id': user_id},
                                 headers=auth)
    else:
        files = {'file': (filepath[filepath.rfind('/') + 1:], open(filepath, 'rb'))}
        json_data = {'json': json.dumps({'format': im_format, 'name': name, 'type': im_type, 'project_id': project_id, 'owner_id': user_id})}
        response = requests.post(REST_base_url + 'images/upload', files=files, data=json_data, headers=auth)

    if response.status_code != 201:
        return -1

    return response.json()['image']['image_id']


def check_image_exists(user_id, project_id, name, category_id, annotation_id):
    response = requests.get(REST_base_url + 'projects/' + str(project_id), headers=auth)
    if response.status_code == 404 or response.json()['project']['owner_id'] != user_id:
        return -1

    response = requests.get(REST_base_url + 'images/byproject_id/' + str(project_id), headers=auth)
    if response.status_code == 404:
        return -1

    images_data = response.json()
    image_id = 0
    for curr_image in images_data['images']:
        if curr_image['name'] == name:
            image_id = curr_image['image_id']

    if image_id == 0:
        return -1

    response = requests.get(REST_base_url + 'annotations/' + str(annotation_id), headers=auth)
    if response.status_code == 404:
        return 0

    annotations_data = response.json()
    if annotations_data['annotation']['project_id'] == project_id and \
       annotations_data['annotation']['category_id'] == category_id and \
       annotations_data['annotation']['image_id'] == image_id:
        return image_id

    return 0


def new_label(user_id, project_id, name):
    response = requests.get(REST_base_url + 'projects/' + str(project_id), headers=auth)
    if response.status_code == 404 or response.json()['project']['owner_id'] != user_id:
        return -1

    response = requests.post(REST_base_url + 'labels', json={'name': name, 'project_id': project_id, 'owner_id': user_id}, headers=auth)
    if response.status_code != 201:
        return -1

    return response.json()['label']['label_id']


def delete_label(user_id, project_id, label_id):
    response = requests.get(REST_base_url + 'projects/' + str(project_id), headers=auth)
    if response.status_code == 404 or response.json()['project']['owner_id'] != user_id:
        return -1

    response = requests.delete(REST_base_url + 'labels/' + str(label_id), headers=auth)
    response = requests.delete(REST_base_url + 'annotations_labels/byfilter/0/' + str(label_id), headers=auth)

    return 0


def new_category(user_id, project_id, name, settings):
    response = requests.get(REST_base_url + 'projects/' + str(project_id), headers=auth)
    if response.status_code == 404 or response.json()['project']['owner_id'] != user_id:
        return -1

    response = requests.post(REST_base_url + 'categories', json={'name': name, 'project_id': project_id, 'owner_id': user_id, 'settings': settings}, headers=auth)
    if response.status_code != 201:
        return -1

    return response.json()['category']['category_id']


def delete_category(user_id, project_id, category_id):
    response = requests.get(REST_base_url + 'projects/' + str(project_id), headers=auth)
    if response.status_code == 404 or response.json()['project']['owner_id'] != user_id:
        return -1

    response = requests.delete(REST_base_url + 'categories/' + str(category_id), headers=auth)
    response = requests.delete(REST_base_url + 'permissions/byfilter/0/catpar/' + str(category_id), headers=auth)

    response = requests.delete(REST_base_url + 'categories_classifications/byfilter/' + str(category_id) + '/0', headers=auth)

    response = requests.get(REST_base_url + 'annotations/bycategory_id/' + str(category_id), headers=auth)
    if response.status_code != 404:
        annotations_data = response.json()
        for curr_annotation in annotations_data['annotations']:
            response = requests.delete(REST_base_url + 'annotations/' + str(curr_annotation['annotation_id']), headers=auth)
            response = requests.delete(REST_base_url + 'permissions/byfilter/0/annpar/' + str(curr_annotation['annotation_id']), headers=auth)
            response = requests.delete(REST_base_url + 'annotations_labels/byfilter/' + str(curr_annotation['annotation_id']) + '/0', headers=auth)

            response = requests.get(REST_base_url + 'layers/byannotation_id/' + str(curr_annotation['annotation_id']), headers=auth)
            if response.status_code != 404:
                layers_data = response.json()
                for curr_layer in layers_data['layers']:
                    response = requests.delete(REST_base_url + 'layers/' + str(curr_layer['layer_id']), headers=auth)
                    response = requests.get(REST_base_url + 'comments/bylayer_id/' + str(curr_layer['layer_id']), headers=auth)
                    if response.status_code != 404:
                        comments_data = response.json()
                        for curr_comment in comments_data['comments']:
                            response = requests.delete(REST_base_url + 'comments/' + str(curr_comment['comment_id']), headers=auth)

    return 0


def get_category_id(user_id, project_id, name):
    response = requests.get(REST_base_url + 'categories/byproject_id/' + str(project_id), headers=auth)
    if response.status_code == 404 or len(response.json()['categories']) == 0:
        return -1

    categories_data = response.json()['categories']
    for curr_category in categories_data:
        if curr_category['name'] == name:
            return curr_category['category_id']

    return -1


def new_annotation(user_id, project_id, category_id, image_id, name, layer_name, layer_sequence, parent_id):
    response = requests.get(REST_base_url + 'projects/' + str(project_id), headers=auth)
    if response.status_code == 404 or response.json()['project']['owner_id'] != user_id:
        return -1, -1

    response = requests.post(REST_base_url + 'annotations',
                             json={'name': name, 'status': 'N', 'shared': '', 'image_id': image_id, 'project_id': project_id,
                                   'category_id': category_id, 'owner_id': user_id},
                             headers=auth)
    if response.status_code != 201:
        return -1, -1

    annotation_id = response.json()['annotation']['annotation_id']

    response = requests.post(REST_base_url + 'layers',
                             json={'name': layer_name, 'data': '', 'image_id': image_id, 'sequence': layer_sequence,
                                   'parent_id': parent_id, 'annotation_id': annotation_id, 'owner_id': user_id},
                             headers=auth)
    if response.status_code != 201:
        response = requests.delete(REST_base_url + 'annotations/' + str(annotation_id), headers=auth)
        return -1, -1

    layer_id = response.json()['layer']['layer_id']

    return annotation_id, layer_id


def delete_annotation(user_id, project_id, category_id, annotation_id):
    response = requests.get(REST_base_url + 'projects/' + str(project_id), headers=auth)
    if response.status_code == 404 or response.json()['project']['owner_id'] != user_id:
        return -1

    response = requests.delete(REST_base_url + 'annotations/' + str(annotation_id), headers=auth)
    response = requests.delete(REST_base_url + 'permissions/byfilter/0/annpar/' + str(annotation_id), headers=auth)
    response = requests.delete(REST_base_url + 'annotations_labels/byfilter/' + str(annotation_id) + '/0', headers=auth)

    response = requests.get(REST_base_url + 'layers/byannotation_id/' + str(annotation_id), headers=auth)
    if response.status_code != 404:
        layers_data = response.json()
        for curr_layer in layers_data['layers']:
            response = requests.delete(REST_base_url + 'layers/' + str(curr_layer['layer_id']), headers=auth)
            response = requests.get(REST_base_url + 'comments/bylayer_id/' + str(curr_layer['layer_id']), headers=auth)
            if response.status_code != 404:
                comments_data = response.json()
                for curr_comment in comments_data['comments']:
                    response = requests.delete(REST_base_url + 'comments/' + str(curr_comment['comment_id']), headers=auth)

    return 0


def get_annotation_id(user_id, project_id, name):
    response = requests.get(REST_base_url + 'annotations/byproject_id/' + str(project_id), headers=auth)
    if response.status_code == 404 or len(response.json()['annotations']) == 0:
        return -1

    annotations_data = response.json()['annotations']
    for curr_annotation in annotations_data:
        if curr_annotation['name'] == name:
            return curr_annotation['annotation_id']

    return -1


def new_image_layer(user_id, project_id, category_id, annotation_id, image_id, name, layer_sequence, parent_id):
    response = requests.get(REST_base_url + 'projects/' + str(project_id), headers=auth)
    if response.status_code == 404 or response.json()['project']['owner_id'] != user_id:
        return -1

    response = requests.get(REST_base_url + 'layers/byannotation_id/' + str(annotation_id), headers=auth)
    if response.status_code == 404:
        return -1
    layers_data = response.json()['layers']

    curr_sequence = layer_sequence
    if curr_sequence == 0:
        curr_sequence = (layers_data[len(layers_data) - 1]['sequence'] + 1)
    response = requests.post(REST_base_url + 'layers',
                             json={'name': name, 'data': '', 'image_id': image_id, 'sequence': curr_sequence,
                                   'parent_id': parent_id, 'annotation_id': annotation_id, 'owner_id': user_id},
                             headers=auth)
    if response.status_code != 201:
        return -1

    return response.json()['layer']['layer_id']


def edit_layer(user_id, project_id, category_id, annotation_id, layer_id, image_id, name, layer_sequence, parent_id):
    response = requests.get(REST_base_url + 'projects/' + str(project_id), headers=auth)
    if response.status_code == 404 or response.json()['project']['owner_id'] != user_id:
        return -1

    response = requests.get(REST_base_url + 'layers/' + str(layer_id), headers=auth)
    if response.status_code == 404:
        return -1

    layers_data = response.json()
    response = requests.put(REST_base_url + 'layers/' + str(layer_id),
                            json={'name': name, 'data': layers_data['layer']['data'], 'image_id': image_id,
                                  'sequence': layer_sequence,
                                  'parent_id': parent_id, 'annotation_id': layers_data['layer']['annotation_id'],
                                  'owner_id': layers_data['layer']['owner_id']},
                            headers=auth)

    if response.status_code != 201:
        return -1

    return layer_id


def get_layer_id(user_id, project_id, annotation_id, name):
    response = requests.get(REST_base_url + 'projects/' + str(project_id), headers=auth)
    if response.status_code == 404 or response.json()['project']['owner_id'] != user_id:
        return -1

    response = requests.get(REST_base_url + 'layers/byannotation_id/' + str(annotation_id))
    if response.status_code == 404:
        return -1
    layers_data = response.json()['layers']

    for curr_layer in layers_data:
        if curr_layer['name'] == name:
            return curr_layer['layer_id']

    return -1


def add_participant(user_id, project_id, category_id, annotation_id, participant_id):
    stype = 'propar'
    type_id = project_id
    if annotation_id:
        stype = 'annpar'
        type_id = annotation_id
    elif category_id:
        stype = 'catpar'
        type_id = category_id

    response = requests.post(REST_base_url + 'permissions', json={'user_id': participant_id, 'type': stype, 'type_id': type_id}, headers=auth)
    if response.status_code != 201:
        return -1

    return response.json()['permission']['user_id']
