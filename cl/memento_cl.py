import json
import requests
from hashlib import sha256


class MementoClient:

    def __init__(self, base_url, username=None, password=None):
        self.base_url = base_url.rstrip('/') + '/'
        self.username = username or ''
        self.password = password or ''
        self.auth = {'x-access-token': ''}

    def login(self, username=None, password=None):
        if username and password:
            self.username = username
            self.password = password

        response = requests.post(url=self.base_url + 'login',
                                 headers={'username': self.username,
                                          'password': sha256(self.password.encode('utf-8')).hexdigest()})
        if response.status_code != 200:
            return -1

        token = json.loads(response.text)
        self.auth = {'x-access-token': token['token']}
        return 0

    def get_user_id(self, username):
        response = requests.get(self.base_url + 'users/byusername/' + username, headers=self.auth)
        if response.status_code == 404:
            return -1

        return response.json()['user']['user_id']

    def get_project_id(self, name):
        response = requests.get(self.base_url + 'projects', headers=self.auth)
        if response.status_code == 404:
            return -1

        for curr_project in response.json()['projects']:
            if curr_project['name'] == name:
                return curr_project['project_id']

        return -1

    def new_project(self, user_id, name, settings):
        response = requests.post(self.base_url + 'projects',
                                 json={'name': name, 'owner_id': user_id, 'settings': settings},
                                 headers=self.auth)
        if response.status_code != 201:
            return -1

        return response.json()['project']['project_id']

    def delete_project(self, user_id, project_id):
        response = requests.get(self.base_url + 'projects/' + str(project_id), headers=self.auth)
        if response.status_code == 404 or response.json()['project']['owner_id'] != user_id:
            return -1

        response = requests.get(self.base_url + 'annotations/byproject_id/' + str(project_id), headers=self.auth)
        if response.status_code != 404:
            annotations_data = response.json()
            for curr_annotation in annotations_data['annotations']:
                response = requests.get(self.base_url + 'layers/byannotation_id/' + str(curr_annotation['annotation_id']), headers=self.auth)
                if response.status_code != 404:
                    layers_data = response.json()
                    for curr_layer in layers_data['layers']:
                        response = requests.get(self.base_url + 'comments/bylayer_id/' + str(curr_layer['layer_id']), headers=self.auth)
                        if response.status_code != 404:
                            comments_data = response.json()
                            for curr_comment in comments_data['comments']:
                                requests.delete(self.base_url + 'comments/' + str(curr_comment['comment_id']), headers=self.auth)
                        requests.delete(self.base_url + 'layers/' + str(curr_layer['layer_id']), headers=self.auth)
                requests.delete(self.base_url + 'annotations_labels/byfilter/' + str(curr_annotation['annotation_id']) + '/0', headers=self.auth)
                requests.delete(self.base_url + 'permissions/byfilter/0/annpar/' + str(curr_annotation['annotation_id']), headers=self.auth)
                requests.delete(self.base_url + 'annotations/' + str(curr_annotation['annotation_id']), headers=self.auth)

        response = requests.get(self.base_url + 'categories/byproject_id/' + str(project_id), headers=self.auth)
        if response.status_code != 404:
            categories_data = response.json()
            for curr_category in categories_data['categories']:
                requests.delete(self.base_url + 'categories_classifications/byfilter/' + str(curr_category['category_id']) + '/0', headers=self.auth)
                requests.delete(self.base_url + 'permissions/byfilter/0/catpar/' + str(curr_category['category_id']), headers=self.auth)
                requests.delete(self.base_url + 'categories/' + str(curr_category['category_id']), headers=self.auth)

        response = requests.get(self.base_url + 'classifications/byproject_id/' + str(project_id), headers=self.auth)
        if response.status_code != 404:
            classifications_data = response.json()
            for curr_classification in classifications_data['classifications']:
                requests.delete(self.base_url + 'classifications/' + str(curr_classification['classification_id']), headers=self.auth)

        response = requests.get(self.base_url + 'images/byproject_id/' + str(project_id), headers=self.auth)
        if response.status_code != 404:
            images_data = response.json()
            for curr_image in images_data['images']:
                requests.delete(self.base_url + 'images/' + str(curr_image['image_id']), headers=self.auth)

        response = requests.get(self.base_url + 'labels/byproject_id/' + str(project_id), headers=self.auth)
        if response.status_code != 404:
            labels_data = response.json()
            for curr_label in labels_data['labels']:
                requests.delete(self.base_url + 'labels/' + str(curr_label['label_id']), headers=self.auth)

        requests.delete(self.base_url + 'permissions/byfilter/0/propar/' + str(project_id), headers=self.auth)
        requests.delete(self.base_url + 'projects/' + str(project_id), headers=self.auth)

        return 0

    def upload_image(self, user_id, project_id, filepath, im_format, name, im_type, url):
        response = requests.get(self.base_url + 'projects/' + str(project_id), headers=self.auth)
        if response.status_code == 404 or response.json()['project']['owner_id'] != user_id:
            return -1

        if im_type == 'E':
            response = requests.post(self.base_url + 'images',
                                     json={'filepath': '', 'format': 0, 'name': name, 'uri': url, 'type': 'E',
                                           'project_id': project_id, 'owner_id': user_id},
                                     headers=self.auth)
        else:
            with open(filepath, 'rb') as f:
                files = {'file': (filepath[filepath.rfind('/') + 1:], f)}
                json_data = {'json': json.dumps({'format': im_format, 'name': name, 'type': im_type,
                                                 'project_id': project_id, 'owner_id': user_id})}
                response = requests.post(self.base_url + 'images/upload', files=files, data=json_data, headers=self.auth)

        if response.status_code != 201:
            return -1

        return response.json()['image']['image_id']

    def check_image_exists(self, user_id, project_id, name, category_id, annotation_id):
        response = requests.get(self.base_url + 'projects/' + str(project_id), headers=self.auth)
        if response.status_code == 404 or response.json()['project']['owner_id'] != user_id:
            return -1

        response = requests.get(self.base_url + 'images/byproject_id/' + str(project_id), headers=self.auth)
        if response.status_code == 404:
            return -1

        images_data = response.json()
        image_id = 0
        for curr_image in images_data['images']:
            if curr_image['name'] == name:
                image_id = curr_image['image_id']

        if image_id == 0:
            return -1

        response = requests.get(self.base_url + 'annotations/' + str(annotation_id), headers=self.auth)
        if response.status_code == 404:
            return 0

        annotations_data = response.json()
        if annotations_data['annotation']['project_id'] == project_id and \
           annotations_data['annotation']['category_id'] == category_id and \
           annotations_data['annotation']['image_id'] == image_id:
            return image_id

        return 0

    def new_classification(self, user_id, project_id, name, ctype, data, settings):
        response = requests.get(self.base_url + 'projects/' + str(project_id), headers=self.auth)
        if response.status_code == 404 or response.json()['project']['owner_id'] != user_id:
            return -1

        response = requests.post(self.base_url + 'classifications',
                                 json={'name': name, 'type': ctype, 'data': data,
                                       'project_id': project_id, 'owner_id': user_id, 'settings': settings},
                                 headers=self.auth)
        if response.status_code != 201:
            return -1

        return response.json()['classification']['classification_id']

    def delete_classification(self, user_id, project_id, classification_id):
        response = requests.get(self.base_url + 'projects/' + str(project_id), headers=self.auth)
        if response.status_code == 404 or response.json()['project']['owner_id'] != user_id:
            return -1

        requests.delete(self.base_url + 'categories_classifications/byfilter/0/' + str(classification_id), headers=self.auth)
        requests.delete(self.base_url + 'classifications/' + str(classification_id), headers=self.auth)

        return 0

    def get_label_id(self, project_id, name):
        response = requests.get(self.base_url + 'labels/byproject_id/' + str(project_id), headers=self.auth)
        if response.status_code == 404:
            return -1

        for curr_label in response.json()['labels']:
            if curr_label['name'] == name:
                return curr_label['label_id']

        return -1

    def new_label(self, user_id, project_id, name):
        response = requests.get(self.base_url + 'projects/' + str(project_id), headers=self.auth)
        if response.status_code == 404 or response.json()['project']['owner_id'] != user_id:
            return -1

        response = requests.post(self.base_url + 'labels',
                                 json={'name': name, 'project_id': project_id, 'owner_id': user_id},
                                 headers=self.auth)
        if response.status_code != 201:
            return -1

        return response.json()['label']['label_id']

    def delete_label(self, user_id, project_id, label_id):
        response = requests.get(self.base_url + 'projects/' + str(project_id), headers=self.auth)
        if response.status_code == 404 or response.json()['project']['owner_id'] != user_id:
            return -1

        requests.delete(self.base_url + 'labels/' + str(label_id), headers=self.auth)
        requests.delete(self.base_url + 'annotations_labels/byfilter/0/' + str(label_id), headers=self.auth)

        return 0

    def new_category(self, user_id, project_id, name, settings):
        response = requests.get(self.base_url + 'projects/' + str(project_id), headers=self.auth)
        if response.status_code == 404 or response.json()['project']['owner_id'] != user_id:
            return -1

        response = requests.post(self.base_url + 'categories',
                                 json={'name': name, 'project_id': project_id, 'owner_id': user_id, 'settings': settings},
                                 headers=self.auth)
        if response.status_code != 201:
            return -1

        return response.json()['category']['category_id']

    def delete_category(self, user_id, project_id, category_id):
        response = requests.get(self.base_url + 'projects/' + str(project_id), headers=self.auth)
        if response.status_code == 404 or response.json()['project']['owner_id'] != user_id:
            return -1

        response = requests.get(self.base_url + 'annotations/bycategory_id/' + str(category_id), headers=self.auth)
        if response.status_code != 404:
            annotations_data = response.json()
            for curr_annotation in annotations_data['annotations']:
                response = requests.get(self.base_url + 'layers/byannotation_id/' + str(curr_annotation['annotation_id']), headers=self.auth)
                if response.status_code != 404:
                    layers_data = response.json()
                    for curr_layer in layers_data['layers']:
                        response = requests.get(self.base_url + 'comments/bylayer_id/' + str(curr_layer['layer_id']), headers=self.auth)
                        if response.status_code != 404:
                            comments_data = response.json()
                            for curr_comment in comments_data['comments']:
                                requests.delete(self.base_url + 'comments/' + str(curr_comment['comment_id']), headers=self.auth)
                        requests.delete(self.base_url + 'layers/' + str(curr_layer['layer_id']), headers=self.auth)
                requests.delete(self.base_url + 'annotations_labels/byfilter/' + str(curr_annotation['annotation_id']) + '/0', headers=self.auth)
                requests.delete(self.base_url + 'permissions/byfilter/0/annpar/' + str(curr_annotation['annotation_id']), headers=self.auth)
                requests.delete(self.base_url + 'annotations/' + str(curr_annotation['annotation_id']), headers=self.auth)

        requests.delete(self.base_url + 'categories_classifications/byfilter/' + str(category_id) + '/0', headers=self.auth)
        requests.delete(self.base_url + 'permissions/byfilter/0/catpar/' + str(category_id), headers=self.auth)
        requests.delete(self.base_url + 'categories/' + str(category_id), headers=self.auth)

        return 0

    def get_category_id(self, user_id, project_id, name):
        response = requests.get(self.base_url + 'categories/byproject_id/' + str(project_id), headers=self.auth)
        if response.status_code == 404 or len(response.json()['categories']) == 0:
            return -1

        categories_data = response.json()['categories']
        for curr_category in categories_data:
            if curr_category['name'] == name:
                return curr_category['category_id']

        return -1

    def new_annotation(self, user_id, project_id, category_id, image_id, name, layer_name, layer_settings, layer_sequence, parent_id, is_group_layer):
        response = requests.get(self.base_url + 'projects/' + str(project_id), headers=self.auth)
        if response.status_code == 404 or response.json()['project']['owner_id'] != user_id:
            return -1, -1

        response = requests.post(self.base_url + 'annotations',
                                 json={'name': name, 'status': 'N', 'shared': '', 'image_id': image_id,
                                       'project_id': project_id, 'category_id': category_id, 'owner_id': user_id},
                                 headers=self.auth)
        if response.status_code != 201:
            return -1, -1

        annotation_id = response.json()['annotation']['annotation_id']

        response = requests.post(self.base_url + 'layers',
                                 json={'name': layer_name, 'data': '', 'image_id': image_id if not is_group_layer else 0,
                                       'settings': layer_settings, 'sequence': layer_sequence, 'parent_id': parent_id,
                                       'annotation_id': annotation_id, 'project_id': project_id, 'owner_id': user_id},
                                 headers=self.auth)
        if response.status_code != 201:
            requests.delete(self.base_url + 'annotations/' + str(annotation_id), headers=self.auth)
            return -1, -1

        layer_id = response.json()['layer']['layer_id']

        return annotation_id, layer_id

    def delete_annotation(self, user_id, project_id, category_id, annotation_id):
        response = requests.get(self.base_url + 'projects/' + str(project_id), headers=self.auth)
        if response.status_code == 404 or response.json()['project']['owner_id'] != user_id:
            return -1

        response = requests.get(self.base_url + 'layers/byannotation_id/' + str(annotation_id), headers=self.auth)
        if response.status_code != 404:
            layers_data = response.json()
            for curr_layer in layers_data['layers']:
                response = requests.get(self.base_url + 'comments/bylayer_id/' + str(curr_layer['layer_id']), headers=self.auth)
                if response.status_code != 404:
                    comments_data = response.json()
                    for curr_comment in comments_data['comments']:
                        requests.delete(self.base_url + 'comments/' + str(curr_comment['comment_id']), headers=self.auth)
                requests.delete(self.base_url + 'layers/' + str(curr_layer['layer_id']), headers=self.auth)

        requests.delete(self.base_url + 'annotations_labels/byfilter/' + str(annotation_id) + '/0', headers=self.auth)
        requests.delete(self.base_url + 'permissions/byfilter/0/annpar/' + str(annotation_id), headers=self.auth)
        requests.delete(self.base_url + 'annotations/' + str(annotation_id), headers=self.auth)

        return 0

    def get_annotation_id(self, user_id, project_id, name):
        response = requests.get(self.base_url + 'annotations/byproject_id/' + str(project_id), headers=self.auth)
        if response.status_code == 404 or len(response.json()['annotations']) == 0:
            return -1

        annotations_data = response.json()['annotations']
        for curr_annotation in annotations_data:
            if curr_annotation['name'] == name:
                return curr_annotation['annotation_id']

        return -1

    def new_image_layer(self, user_id, project_id, category_id, annotation_id, image_id, name, layer_settings, layer_sequence, parent_id):
        response = requests.get(self.base_url + 'projects/' + str(project_id), headers=self.auth)
        if response.status_code == 404 or response.json()['project']['owner_id'] != user_id:
            return -1

        response = requests.get(self.base_url + 'layers/byannotation_id/' + str(annotation_id), headers=self.auth)
        if response.status_code == 404:
            return -1
        layers_data = response.json()['layers']

        curr_sequence = layer_sequence
        if curr_sequence == -1:
            curr_sequence = (layers_data[len(layers_data) - 1]['sequence'] + 1)
        response = requests.post(self.base_url + 'layers',
                                 json={'name': name, 'data': '', 'image_id': image_id, 'settings': layer_settings,
                                       'sequence': curr_sequence, 'parent_id': parent_id,
                                       'annotation_id': annotation_id, 'project_id': project_id, 'owner_id': user_id},
                                 headers=self.auth)
        if response.status_code != 201:
            return -1

        return response.json()['layer']['layer_id']

    def edit_layer(self, user_id, project_id, category_id, annotation_id, layer_id, image_id, name, layer_settings, layer_sequence, parent_id):
        response = requests.get(self.base_url + 'projects/' + str(project_id), headers=self.auth)
        if response.status_code == 404 or response.json()['project']['owner_id'] != user_id:
            return -1

        response = requests.get(self.base_url + 'layers/' + str(layer_id), headers=self.auth)
        if response.status_code == 404:
            return -1

        layers_data = response.json()
        response = requests.put(self.base_url + 'layers/' + str(layer_id),
                                json={'name': name, 'data': layers_data['layer']['data'], 'image_id': image_id,
                                      'settings': layer_settings, 'sequence': layer_sequence, 'parent_id': parent_id,
                                      'annotation_id': layers_data['layer']['annotation_id'],
                                      'project_id': layers_data['layer']['project_id'],
                                      'owner_id': layers_data['layer']['owner_id']},
                                headers=self.auth)

        if response.status_code != 201:
            return -1

        return layer_id

    def get_layer_id(self, user_id, project_id, annotation_id, name):
        response = requests.get(self.base_url + 'projects/' + str(project_id), headers=self.auth)
        if response.status_code == 404 or response.json()['project']['owner_id'] != user_id:
            return -1

        response = requests.get(self.base_url + 'layers/byannotation_id/' + str(annotation_id), headers=self.auth)
        if response.status_code == 404:
            return -1
        layers_data = response.json()['layers']

        for curr_layer in layers_data:
            if curr_layer['name'] == name:
                return curr_layer['layer_id']

        return -1

    def get_classifications(self, user_id, project_id, category_id):
        response = requests.get(self.base_url + 'projects/' + str(project_id), headers=self.auth)
        if response.status_code == 404 or response.json()['project']['owner_id'] != user_id:
            return None

        response = requests.get(self.base_url + 'classifications/byproject_id/' + str(project_id), headers=self.auth)
        if response.status_code == 404:
            return []
        all_classifications = {c['classification_id']: c for c in response.json()['classifications']}

        response = requests.get(self.base_url + 'categories_classifications/byfilter/' + str(category_id) + '/0', headers=self.auth)
        if response.status_code == 404:
            return []

        result = []
        for curr_cateclas in response.json()['categories_classifications']:
            cla = all_classifications.get(curr_cateclas['classification_id'])
            if cla and cla['type'] == 'M':
                result.append(cla['name'])

        return result

    def set_classifications(self, user_id, project_id, category_id, classifications_list):
        response = requests.get(self.base_url + 'projects/' + str(project_id), headers=self.auth)
        if response.status_code == 404 or response.json()['project']['owner_id'] != user_id:
            return -1

        response = requests.get(self.base_url + 'classifications/byproject_id/' + str(project_id), headers=self.auth)
        if response.status_code == 404:
            return -1

        classification_data = response.json()
        result = []
        for classification in classifications_list:
            for curr_category in classification_data['classifications']:
                if curr_category['name'] == classification:
                    result.append(curr_category['classification_id'])
                    break

        if len(result) == len(classifications_list):
            requests.delete(self.base_url + 'categories_classifications/byfilter/' + str(category_id) + '/0', headers=self.auth)
            for classification in result:
                response = requests.post(self.base_url + 'categories_classifications',
                                         json={'category_id': category_id, 'classification_id': classification},
                                         headers=self.auth)
                if response.status_code != 201:
                    return -1

            return len(result)

        return -1

    def get_annotation_labels(self, user_id, project_id, annotation_id):
        response = requests.get(self.base_url + 'projects/' + str(project_id), headers=self.auth)
        if response.status_code == 404 or response.json()['project']['owner_id'] != user_id:
            return None

        response = requests.get(self.base_url + 'labels/byproject_id/' + str(project_id), headers=self.auth)
        if response.status_code == 404:
            return []
        all_labels = {l['label_id']: l for l in response.json()['labels']}

        response = requests.get(self.base_url + 'annotations_labels/byfilter/' + str(annotation_id) + '/0', headers=self.auth)
        if response.status_code == 404:
            return []

        result = []
        for curr_annlab in response.json()['annotations_labels']:
            label = all_labels.get(curr_annlab['label_id'])
            if label:
                result.append(label['name'])

        return result

    def set_annotation_labels(self, user_id, project_id, annotation_id, labels_list):
        response = requests.get(self.base_url + 'projects/' + str(project_id), headers=self.auth)
        if response.status_code == 404 or response.json()['project']['owner_id'] != user_id:
            return -1

        response = requests.get(self.base_url + 'labels/byproject_id/' + str(project_id), headers=self.auth)
        if response.status_code == 404:
            return -1

        labels_data = response.json()
        result = []
        for label in labels_list:
            for curr_label in labels_data['labels']:
                if curr_label['name'] == label:
                    result.append(curr_label['label_id'])
                    break

        if len(result) == len(labels_list):
            requests.delete(self.base_url + 'annotations_labels/byfilter/' + str(annotation_id) + '/0', headers=self.auth)
            for label in result:
                response = requests.post(self.base_url + 'annotations_labels',
                                         json={'annotation_id': annotation_id, 'label_id': label},
                                         headers=self.auth)
                if response.status_code != 201:
                    return -1

            return len(result)

        return -1

    def add_participant(self, user_id, project_id, category_id, annotation_id, participant_id):
        stype = 'propar'
        type_id = project_id
        if annotation_id:
            stype = 'annpar'
            type_id = annotation_id
        elif category_id:
            stype = 'catpar'
            type_id = category_id

        response = requests.post(self.base_url + 'permissions',
                                 json={'user_id': participant_id, 'type': stype, 'type_id': type_id},
                                 headers=self.auth)
        if response.status_code != 201:
            return -1

        return response.json()['permission']['user_id']

    def project_summary(self, project_id):
        response = requests.get(self.base_url + 'utilities/project_summary/' + str(project_id), headers=self.auth)
        if response.status_code != 200:
            return None

        return response.json()

    def project_data(self, project_id):
        response = requests.get(self.base_url + 'utilities/project_data/' + str(project_id), headers=self.auth)
        if response.status_code != 200:
            return None

        return response.json()['project_data']

    def project_rois(self, project_id):
        response = requests.get(self.base_url + 'utilities/project_rois/' + str(project_id), headers=self.auth)
        if response.status_code != 200:
            return None

        return response.json()['project_rois']

    def project_comments(self, project_id):
        response = requests.get(self.base_url + 'utilities/project_comments/' + str(project_id), headers=self.auth)
        if response.status_code != 200:
            return None

        return response.json()['project_comments']

    # ------------------------------------------------------------------
    # Import helpers — idempotent wrappers for writing import scripts.
    # Each method checks whether the entity already exists and only
    # creates it if it does not, making scripts safe to re-run after a
    # partial failure without accumulating duplicates.
    # ------------------------------------------------------------------

    def get_or_create_project(self, user_id, name, settings=''):
        """Return the project_id for an existing project, or create it."""
        project_id = self.get_project_id(name)
        if project_id == -1:
            project_id = self.new_project(user_id, name, settings)
        return project_id

    def get_or_create_category(self, user_id, project_id, name, settings=''):
        """Return the category_id for an existing category, or create it."""
        category_id = self.get_category_id(user_id, project_id, name)
        if category_id == -1:
            category_id = self.new_category(user_id, project_id, name, settings)
        return category_id

    def get_or_upload_image(self, user_id, project_id, filepath, im_format, name, im_type='', url=''):
        """Return the image_id if an image with this name already exists in the
        project, otherwise upload it.  Checks by name only — no category or
        annotation constraint — so it is safe to call before an annotation
        has been created."""
        response = requests.get(self.base_url + 'images/byproject_id/' + str(project_id), headers=self.auth)
        if response.status_code == 200:
            for img in response.json()['images']:
                if img['name'] == name:
                    return img['image_id']
        return self.upload_image(user_id, project_id, filepath, im_format, name, im_type, url)

    def get_or_create_annotation(self, user_id, project_id, category_id, image_id, name,
                                  layer_name, layer_settings='', layer_sequence=1, parent_id=0,
                                  is_group_layer=False):
        """Return (annotation_id, layer_id) for an existing annotation, or create
        it together with its first layer.  When the annotation already exists
        layer_id is -1; use get_or_create_layer to add further layers."""
        annotation_id = self.get_annotation_id(user_id, project_id, name)
        if annotation_id == -1:
            return self.new_annotation(user_id, project_id, category_id, image_id, name,
                                       layer_name, layer_settings, layer_sequence, parent_id,
                                       is_group_layer)
        return annotation_id, -1

    def get_or_create_layer(self, user_id, project_id, category_id, annotation_id, image_id,
                             name, layer_settings='', layer_sequence=-1, parent_id=0):
        """Return the layer_id for an existing layer, or create it.
        layer_sequence=-1 appends after the last existing layer."""
        layer_id = self.get_layer_id(user_id, project_id, annotation_id, name)
        if layer_id == -1:
            layer_id = self.new_image_layer(user_id, project_id, category_id, annotation_id,
                                            image_id, name, layer_settings, layer_sequence,
                                            parent_id)
        return layer_id