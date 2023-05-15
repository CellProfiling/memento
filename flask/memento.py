from flask import Flask, jsonify, request, abort
from hashlib import sha256
from minio import Minio
from werkzeug.utils import secure_filename
from werkzeug.exceptions import HTTPException
import jwt
import time
from datetime import timedelta
from functools import wraps
import logging
import model
import os
import PIL
from PIL import Image, ImageFile
import sqlalchemy as sqla


app = Flask(__name__)

app.config['MEMENTO_FLASK_AUTH_TOKEN_KEY'] = os.environ.get("MEMENTO_FLASK_AUTH_TOKEN_KEY")
app.config['MEMENTO_FLASK_WHITE_LISTED_TOKEN'] = os.environ.get("MEMENTO_FLASK_WHITE_LISTED_TOKEN")
app.config['MEMENTO_FLASK_UPLOAD_FOLDER'] = "/opt/memento/images/"
app.config['S3_URL'] = os.environ.get("S3_URL")
app.config['S3_BUCKET'] = os.environ.get("S3_BUCKET")
app.config['S3_ACCESS_KEY'] = os.environ.get("S3_ACCESS_KEY")
app.config['S3_SECRET_KEY'] = os.environ.get("S3_SECRET_KEY")

client = Minio(app.config['S3_URL'], app.config['S3_ACCESS_KEY'], app.config['S3_SECRET_KEY'])

gunicorn_logger = logging.getLogger('gunicorn.error')
app.logger.handlers = gunicorn_logger.handlers
app.logger.setLevel(gunicorn_logger.level)

ImageFile.LOAD_TRUNCATED_IMAGES = True
PIL.Image.MAX_IMAGE_PIXELS = 10000000000


def token_required(f):
    @wraps(f)
    def decorator(*args, **kwargs):
        token = None
        if 'x-access-token' in request.headers:
            token = request.headers['x-access-token']
        if not token:
            abort(401)
        try:
            if token == app.config['MEMENTO_FLASK_WHITE_LISTED_TOKEN']:
                app.logger.info('memento web: ' + f.__name__)
                return f(*args, **kwargs)
            data = jwt.decode(token, app.config['MEMENTO_FLASK_AUTH_TOKEN_KEY'])
            if int(data['exp']) != 0 and time.time() > int(data['exp']):
                abort(401)
            conn = model.engine.connect()
            sql = sqla.select([model.users.c.username]).where(model.users.c.user_id == data['user_id'])
            result = conn.execute(sql)
            if result.rowcount == 0:
                abort(401)
            user = result.first()
            app.logger.info('memento ' + user['username'] + ': ' + f.__name__)
            return f(*args, **kwargs)
        except Exception as e:
            app.logger.error(e)
            if isinstance(e, HTTPException):
                abort(e.code)
            else:
                abort(500)

    return decorator


@app.route('/memento/login', methods=['GET', 'POST'])
def login():
    headers = request.headers
    username = headers.get("username")
    password = headers.get("password")
    if not username or not password:
        abort(401)
    conn = model.engine.connect()
    sql = sqla.select([model.users.c.user_id, model.users.c.password]).where(model.users.c.username == username).where(
        model.users.c.password == password)
    result = conn.execute(sql)
    if result.rowcount == 0:
        abort(401)
    user = result.first()

    token = jwt.encode({'user_id': user['user_id'],
                        'exp': (time.time() + 86400)},
                       app.config['MEMENTO_FLASK_AUTH_TOKEN_KEY'])
    return jsonify({'token': token.decode('UTF-8')}), 200


@app.route('/memento/users', methods=['GET'])
@token_required
def get_users():
    conn = model.engine.connect()
    sql = sqla.select([model.users.c.user_id, model.users.c.username, model.users.c.name, model.users.c.email, model.users.c.settings])
    result = conn.execute(sql)
    return jsonify({'users': [dict(row) for row in result]}), 200


@app.route('/memento/users/<int:user_id>', methods=['GET'])
@token_required
def get_user(user_id):
    conn = model.engine.connect()
    sql = sqla.select([model.users.c.user_id, model.users.c.username, model.users.c.name, model.users.c.email, model.users.c.settings]).where(
        model.users.c.user_id == user_id)
    result = conn.execute(sql)
    if result.rowcount == 0:
        abort(404)
    return jsonify({'user': dict(row) for row in result}), 200


@app.route('/memento/users', methods=['POST'])
@token_required
def create_user():
    if not request.json or not 'username' or not 'name' in request.json or not 'email' in request.json or not 'password' in request.json or not 'settings' in request.json:
        abort(400)
    new_user = {
        'username': request.json['username'],
        'name': request.json['name'],
        'email': request.json['email'],
        'settings': request.json['settings'],
    }
    conn = model.engine.connect()
    sql = model.users.insert().values(username=new_user['username'], name=new_user['name'], email=new_user['email'], settings=new_user['settings'],
                                      password=sha256(request.json['password'].encode('utf-8')).hexdigest())
    result = conn.execute(sql)
    new_user['user_id'] = result.inserted_primary_key[0]
    return jsonify({'user': new_user}), 201


@app.route('/memento/users/<int:user_id>', methods=['PUT'])
@token_required
def update_user(user_id):
    if not request.json or not 'username' or not 'name' in request.json or not 'email' in request.json or not 'password' in request.json or not 'settings' in request.json:
        abort(400)
    updated_user = {
        'user_id': user_id,
        'username': request.json['username'],
        'name': request.json['name'],
        'email': request.json['email'],
        'settings': request.json['settings'],
    }
    conn = model.engine.connect()
    sql = model.users.update().values(username=updated_user['username'], name=updated_user['name'], email=updated_user['email'], settings=updated_user['settings'],
                                      password=sha256(request.json['password'].encode('utf-8')).hexdigest()). \
        where(model.users.c.user_id == user_id)
    conn.execute(sql)
    return jsonify({'user': updated_user}), 201


@app.route('/memento/users/<int:user_id>', methods=['DELETE'])
@token_required
def delete_user(user_id):
    conn = model.engine.connect()
    sql = model.users.delete().where(model.users.c.user_id == user_id)
    conn.execute(sql)
    return "", 204


@app.route('/memento/users/byusername/<string:username>', methods=['GET'])
@token_required
def get_user_byusername(username):
    conn = model.engine.connect()
    sql = sqla.select([model.users.c.user_id, model.users.c.username, model.users.c.name, model.users.c.password, model.users.c.email, model.users.c.settings]). \
        where(model.users.c.username == username)
    result = conn.execute(sql)
    if result.rowcount == 0:
        abort(404)
    return jsonify({'user': dict(row) for row in result}), 200


@app.route('/memento/permissions', methods=['GET'])
@token_required
def get_permissions():
    conn = model.engine.connect()
    sql = sqla.select([model.permissions.c.user_id, model.permissions.c.type, model.permissions.c.type_id])
    result = conn.execute(sql)
    return jsonify({'permissions': [dict(row) for row in result]}), 200


@app.route('/memento/permissions/<int:user_id>/<string:stype>/<int:type_id>', methods=['GET'])
@token_required
def get_permission(user_id, stype, type_id):
    conn = model.engine.connect()
    sql = sqla.select([model.permissions.c.user_id, model.permissions.c.type, model.permissions.c.type_id]).where(
        model.permissions.c.user_id == user_id).where(model.permissions.c.type == stype).where(
        model.permissions.c.type_id == type_id)
    result = conn.execute(sql)
    if result.rowcount == 0:
        abort(404)
    return jsonify({'permission': dict(row) for row in result}), 200


@app.route('/memento/permissions', methods=['POST'])
@token_required
def create_permission():
    if not request.json or not 'user_id' in request.json or not 'type' in request.json or not 'type_id' in request.json:
        abort(400)
    new_permission = {
        'user_id': request.json['user_id'],
        'type': request.json['type'],
        'type_id': request.json['type_id'],
    }
    conn = model.engine.connect()
    sql = model.permissions.insert().values(user_id=new_permission['user_id'], type=new_permission['type'], type_id=new_permission['type_id'])
    result = conn.execute(sql)
    return jsonify({'permission': new_permission}), 201


@app.route('/memento/permissions/<int:user_id>/<string:stype>/<int:type_id>', methods=['DELETE'])
@token_required
def delete_permission(user_id, stype, type_id):
    conn = model.engine.connect()
    sql = model.permissions.delete().where(model.permissions.c.user_id == user_id).where(
        model.permissions.c.type == stype).where(model.permissions.c.type_id == type_id)
    conn.execute(sql)
    return "", 204


@app.route('/memento/permissions/byfilter/<int:user_id>/<string:stype>/<int:type_id>', methods=['GET'])
@token_required
def get_permissions_byfilter(user_id, stype, type_id):
    conn = model.engine.connect()
    sql = sqla.select([model.permissions.c.user_id, model.permissions.c.type, model.permissions.c.type_id])
    if (user_id > 0):
        sql = sql.where(model.permissions.c.user_id == user_id)
    if (stype != '' and stype != 'none'):
        sql = sql.where(model.permissions.c.type == stype)
    if (type_id > 0):
        sql = sql.where(model.permissions.c.type_id == type_id)
    result = conn.execute(sql)
    return jsonify({'permissions': [dict(row) for row in result]}), 200


@app.route('/memento/permissions/byfilter/<int:user_id>/<string:stype>/<int:type_id>', methods=['DELETE'])
@token_required
def delete_permissions_byfilter(user_id, stype, type_id):
    conn = model.engine.connect()
    sql = model.permissions.delete()
    if (user_id > 0):
        sql = sql.where(model.permissions.c.user_id == user_id)
    if (stype != '' and stype != 'none'):
        sql = sql.where(model.permissions.c.type == stype)
    if (type_id > 0):
        sql = sql.where(model.permissions.c.type_id == type_id)
    conn.execute(sql)
    return "", 204


@app.route('/memento/projects', methods=['GET'])
@token_required
def get_projects():
    conn = model.engine.connect()
    sql = sqla.select([model.projects.c.project_id, model.projects.c.name, model.projects.c.owner_id])
    result = conn.execute(sql)
    return jsonify({'projects': [dict(row) for row in result]}), 200


@app.route('/memento/projects/<int:project_id>', methods=['GET'])
@token_required
def get_project(project_id):
    conn = model.engine.connect()
    sql = sqla.select([model.projects.c.project_id, model.projects.c.name, model.projects.c.owner_id, model.projects.c.settings]).where(
        model.projects.c.project_id == project_id)
    result = conn.execute(sql)
    if result.rowcount == 0:
        abort(404)
    return jsonify({'project': dict(row) for row in result}), 200


@app.route('/memento/projects', methods=['POST'])
@token_required
def create_project():
    if not request.json or not 'name' in request.json or not 'owner_id' in request.json or not 'settings' in request.json:
        abort(400)
    new_project = {
        'name': request.json['name'],
        'owner_id': request.json['owner_id'],
        'settings': request.json['settings'],
    }
    conn = model.engine.connect()
    sql = model.projects.insert().values(name=new_project['name'], owner_id=new_project['owner_id'], settings=new_project['settings'])
    result = conn.execute(sql)
    new_project['project_id'] = result.inserted_primary_key[0]
    return jsonify({'project': new_project}), 201


@app.route('/memento/projects/<int:project_id>', methods=['PUT'])
@token_required
def update_project(project_id):
    if not request.json or not 'name' in request.json or not 'owner_id' in request.json or not 'settings' in request.json:
        abort(400)
    updated_project = {
        'project_id': project_id,
        'name': request.json['name'],
        'owner_id': request.json['owner_id'],
        'settings': request.json['settings'],
    }
    conn = model.engine.connect()
    sql = model.projects.update().values(name=updated_project['name'], owner_id=updated_project['owner_id'], settings=updated_project['settings']). \
        where(model.projects.c.project_id == project_id)
    conn.execute(sql)
    return jsonify({'project': updated_project}), 201


@app.route('/memento/projects/<int:project_id>', methods=['DELETE'])
@token_required
def delete_project(project_id):
    conn = model.engine.connect()
    sql = model.projects.delete().where(model.projects.c.project_id == project_id)
    conn.execute(sql)
    return "", 204

@app.route('/memento/categories', methods=['GET'])
@token_required
def get_categories():
    conn = model.engine.connect()
    sql = sqla.select([model.categories.c.category_id, model.categories.c.name, model.categories.c.project_id, model.categories.c.owner_id, model.categories.c.settings])
    result = conn.execute(sql)
    return jsonify({'categories': [dict(row) for row in result]}), 200


@app.route('/memento/categories/<int:category_id>', methods=['GET'])
@token_required
def get_category(category_id):
    conn = model.engine.connect()
    sql = sqla.select([model.categories.c.category_id, model.categories.c.name, model.categories.c.project_id, model.categories.c.owner_id, model.categories.c.settings]).where(
        model.categories.c.category_id == category_id)
    result = conn.execute(sql)
    if result.rowcount == 0:
        abort(404)
    return jsonify({'category': dict(row) for row in result}), 200


@app.route('/memento/categories', methods=['POST'])
@token_required
def create_category():
    if not request.json or not 'name' in request.json or not 'project_id' in request.json or not 'owner_id' in request.json or not 'settings' in request.json:
        abort(400)
    new_category = {
        'name': request.json['name'],
        'project_id': request.json['project_id'],
        'owner_id': request.json['owner_id'],
        'settings': request.json['settings'],
    }
    conn = model.engine.connect()
    sql = model.categories.insert().values(name=new_category['name'], project_id=new_category['project_id'], owner_id=new_category['owner_id'], settings=new_category['settings'])
    result = conn.execute(sql)
    new_category['category_id'] = result.inserted_primary_key[0]
    return jsonify({'category': new_category}), 201


@app.route('/memento/categories/<int:category_id>', methods=['PUT'])
@token_required
def update_category(category_id):
    if not request.json or not 'name' in request.json or not 'project_id' in request.json or not 'owner_id' in request.json or not 'settings' in request.json:
        abort(400)
    updated_category = {
        'category_id': category_id,
        'name': request.json['name'],
        'project_id': request.json['project_id'],
        'owner_id': request.json['owner_id'],
        'settings': request.json['settings'],
    }
    conn = model.engine.connect()
    sql = model.categories.update().values(name=updated_category['name'], project_id=updated_category['project_id'], owner_id=updated_category['owner_id'], settings=updated_category['settings']). \
        where(model.categories.c.category_id == category_id)
    conn.execute(sql)
    return jsonify({'category': updated_category}), 201


@app.route('/memento/categories/<int:category_id>', methods=['DELETE'])
@token_required
def delete_category(category_id):
    conn = model.engine.connect()
    sql = model.categories.delete().where(model.categories.c.category_id == category_id)
    conn.execute(sql)
    return "", 204


@app.route('/memento/categories/byproject_id/<int:project_id>', methods=['GET'])
@token_required
def get_category_byproject_id(project_id):
    conn = model.engine.connect()
    sql = sqla.select([model.categories.c.category_id, model.categories.c.name, model.categories.c.project_id, model.categories.c.owner_id, model.categories.c.settings]).where(
        model.categories.c.project_id == project_id)
    result = conn.execute(sql)
    if result.rowcount == 0:
        abort(404)
    return jsonify({'categories': [dict(row) for row in result]}), 200


@app.route('/memento/classifications', methods=['GET'])
@token_required
def get_classifications():
    conn = model.engine.connect()
    sql = sqla.select([model.classifications.c.classification_id, model.classifications.c.name, model.classifications.c.type, model.classifications.c.data,
                       model.classifications.c.project_id, model.classifications.c.owner_id, model.classifications.c.settings])
    result = conn.execute(sql)
    return jsonify({'classifications': [dict(row) for row in result]}), 200


@app.route('/memento/classifications/<int:classification_id>', methods=['GET'])
@token_required
def get_classification(classification_id):
    conn = model.engine.connect()
    sql = sqla.select([model.classifications.c.classification_id, model.classifications.c.name, model.classifications.c.type, model.classifications.c.data,
                       model.classifications.c.project_id, model.classifications.c.owner_id, model.classifications.c.settings]).where(
        model.classifications.c.classification_id == classification_id)
    result = conn.execute(sql)
    if result.rowcount == 0:
        abort(404)
    return jsonify({'classification': dict(row) for row in result}), 200


@app.route('/memento/classifications', methods=['POST'])
@token_required
def create_classification():
    if not request.json or not 'name' in request.json or not 'type' in request.json or not 'data' in request.json or not 'project_id' in request.json or not 'owner_id' in request.json or not 'settings' in request.json:
        abort(400)
    new_classification = {
        'name': request.json['name'],
        'type': request.json['type'],
        'data': request.json['data'],
        'project_id': request.json['project_id'],
        'owner_id': request.json['owner_id'],
        'settings': request.json['settings'],
    }
    conn = model.engine.connect()
    sql = model.classifications.insert().values(name=new_classification['name'], type=new_classification['type'], data=new_classification['data'], project_id=new_classification['project_id'], owner_id=new_classification['owner_id'], settings=new_classification['settings'])
    result = conn.execute(sql)
    new_classification['classification_id'] = result.inserted_primary_key[0]
    return jsonify({'classification': new_classification}), 201


@app.route('/memento/classifications/<int:classification_id>', methods=['PUT'])
@token_required
def update_classification(classification_id):
    if not request.json or not 'name' in request.json or not 'type' in request.json or not 'data' in request.json or not 'project_id' in request.json or not 'owner_id' in request.json or not 'settings' in request.json:
        abort(400)
    updated_classification = {
        'classification_id': classification_id,
        'name': request.json['name'],
        'type': request.json['type'],
        'data': request.json['data'],
        'project_id': request.json['project_id'],
        'owner_id': request.json['owner_id'],
        'settings': request.json['settings'],
    }
    conn = model.engine.connect()
    sql = model.classifications.update().values(name=updated_classification['name'], type=updated_classification['type'], data=updated_classification['data'], project_id=updated_classification['project_id'], owner_id=updated_classification['owner_id'], settings=updated_classification['settings']). \
        where(model.classifications.c.classification_id == classification_id)
    conn.execute(sql)
    return jsonify({'classification': updated_classification}), 201


@app.route('/memento/classifications/<int:classification_id>', methods=['DELETE'])
@token_required
def delete_classification(classification_id):
    conn = model.engine.connect()
    sql = model.classifications.delete().where(model.classifications.c.classification_id == classification_id)
    conn.execute(sql)
    return "", 204


@app.route('/memento/classifications/byproject_id/<int:project_id>', methods=['GET'])
@token_required
def get_classification_byproject_id(project_id):
    conn = model.engine.connect()
    sql = sqla.select([model.classifications.c.classification_id, model.classifications.c.name, model.classifications.c.type, model.classifications.c.data,
                       model.classifications.c.project_id, model.classifications.c.owner_id, model.classifications.c.settings]).where(
        model.classifications.c.project_id == project_id)
    result = conn.execute(sql)
    if result.rowcount == 0:
        abort(404)
    return jsonify({'classifications': [dict(row) for row in result]}), 200


@app.route('/memento/classifications/bycategory_id/<int:category_id>', methods=['GET'])
@token_required
def get_classification_bycategory_id(category_id):
    conn = model.engine.connect()
    sql = sqla.select([model.classifications.c.classification_id, model.classifications.c.name, model.classifications.c.type, model.classifications.c.data,
                       model.classifications.c.project_id, model.classifications.c.owner_id, model.classifications.c.settings]).where(
        model.classifications.c.category_id == category_id)
    result = conn.execute(sql)
    if result.rowcount == 0:
        abort(404)
    return jsonify({'classifications': [dict(row) for row in result]}), 200


@app.route('/memento/categories_classifications', methods=['GET'])
@token_required
def get_categories_classifications():
    conn = model.engine.connect()
    sql = sqla.select([model.categories_classifications.c.category_id, model.categories_classifications.c.classification_id])
    result = conn.execute(sql)
    return jsonify({'categories_classifications': [dict(row) for row in result]}), 200


@app.route('/memento/categories_classifications/<int:category_id>/<int:classification_id>', methods=['GET'])
@token_required
def get_category_classification(category_id, classification_id):
    conn = model.engine.connect()
    sql = sqla.select([model.categories_classifications.c.category_id, model.categories_classifications.c.classification_id]).where(
        model.categories_classifications.c.category_id == category_id).where(
        model.categories_classifications.c.classification_id == classification_id)
    result = conn.execute(sql)
    if result.rowcount == 0:
        abort(404)
    return jsonify({'category_classification': dict(row) for row in result}), 200


@app.route('/memento/categories_classifications', methods=['POST'])
@token_required
def create_category_classification():
    if not request.json or not 'category_id' in request.json or not 'classification_id' in request.json:
        abort(400)
    new_category_classification = {
        'category_id': request.json['category_id'],
        'classification_id': request.json['classification_id'],
    }
    conn = model.engine.connect()
    sql = model.categories_classifications.insert().values(category_id=new_category_classification['category_id'], classification_id=new_category_classification['classification_id'])
    result = conn.execute(sql)
    return jsonify({'category_classification': new_category_classification}), 201


@app.route('/memento/categories_classifications/<int:category_id>/<int:classification_id>', methods=['DELETE'])
@token_required
def delete_category_classification(category_id, classification_id):
    conn = model.engine.connect()
    sql = model.categories_classifications.delete().where(model.categories_classifications.c.category_id == category_id).where(
        model.categories_classifications.c.classification_id == classification_id)
    conn.execute(sql)
    return "", 204


@app.route('/memento/categories_classifications/byfilter/<int:category_id>/<int:classification_id>', methods=['GET'])
@token_required
def get_categories_classifications_byfilter(category_id, classification_id):
    conn = model.engine.connect()
    sql = sqla.select([model.categories_classifications.c.category_id, model.categories_classifications.c.classification_id])
    if (category_id > 0):
        sql = sql.where(model.categories_classifications.c.category_id == category_id)
    if (classification_id > 0):
        sql = sql.where(model.categories_classifications.c.classification_id == classification_id)
    result = conn.execute(sql)
    return jsonify({'categories_classifications': [dict(row) for row in result]}), 200


@app.route('/memento/categories_classifications/byfilter/<int:category_id>/<int:classification_id>', methods=['DELETE'])
@token_required
def delete_categories_classifications_byfilter(category_id, classification_id):
    conn = model.engine.connect()
    sql = model.categories_classifications.delete()
    if (category_id > 0):
        sql = sql.where(model.categories_classifications.c.category_id == category_id)
    if (classification_id > 0):
        sql = sql.where(model.categories_classifications.c.classification_id == classification_id)
    conn.execute(sql)
    return "", 204


@app.route('/memento/labels', methods=['GET'])
@token_required
def get_labels():
    conn = model.engine.connect()
    sql = sqla.select([model.labels.c.label_id, model.labels.c.name, model.labels.c.project_id, model.labels.c.owner_id])
    result = conn.execute(sql)
    return jsonify({'labels': [dict(row) for row in result]}), 200


@app.route('/memento/labels/<int:label_id>', methods=['GET'])
@token_required
def get_label(label_id):
    conn = model.engine.connect()
    sql = sqla.select([model.labels.c.label_id, model.labels.c.name, model.labels.c.project_id, model.labels.c.owner_id]).where(
        model.labels.c.label_id == label_id)
    result = conn.execute(sql)
    if result.rowcount == 0:
        abort(404)
    return jsonify({'label': dict(row) for row in result}), 200


@app.route('/memento/labels', methods=['POST'])
@token_required
def create_label():
    if not request.json or not 'name' in request.json or not 'project_id' in request.json or not 'owner_id' in request.json:
        abort(400)
    new_label = {
        'name': request.json['name'],
        'project_id': request.json['project_id'],
        'owner_id': request.json['owner_id'],
    }
    conn = model.engine.connect()
    sql = model.labels.insert().values(name=new_label['name'], project_id=new_label['project_id'], owner_id=new_label['owner_id'])
    result = conn.execute(sql)
    new_label['label_id'] = result.inserted_primary_key[0]
    return jsonify({'label': new_label}), 201


@app.route('/memento/labels/<int:label_id>', methods=['PUT'])
@token_required
def update_label(label_id):
    if not request.json or not 'name' in request.json or not 'project_id' in request.json or not 'owner_id' in request.json:
        abort(400)
    updated_label = {
        'label_id': label_id,
        'name': request.json['name'],
        'project_id': request.json['project_id'],
        'owner_id': request.json['owner_id'],
    }
    conn = model.engine.connect()
    sql = model.labels.update().values(name=updated_label['name'], project_id=updated_label['project_id'], owner_id=updated_label['owner_id']). \
        where(model.labels.c.label_id == label_id)
    conn.execute(sql)
    return jsonify({'label': updated_label}), 201


@app.route('/memento/labels/<int:label_id>', methods=['DELETE'])
@token_required
def delete_label(label_id):
    conn = model.engine.connect()
    sql = model.labels.delete().where(model.labels.c.label_id == label_id)
    conn.execute(sql)
    return "", 204


@app.route('/memento/labels/byproject_id/<int:project_id>', methods=['GET'])
@token_required
def get_label_byproject_id(project_id):
    conn = model.engine.connect()
    sql = sqla.select([model.labels.c.label_id, model.labels.c.name, model.labels.c.project_id, model.labels.c.owner_id]).where(
        model.labels.c.project_id == project_id)
    result = conn.execute(sql)
    if result.rowcount == 0:
        abort(404)
    return jsonify({'labels': [dict(row) for row in result]}), 200


@app.route('/memento/images', methods=['GET'])
@token_required
def get_images():
    conn = model.engine.connect()
    sql = sqla.select([model.images.c.image_id, model.images.c.name, model.images.c.uri, model.images.c.type, model.images.c.resolution, model.images.c.project_id, model.images.c.owner_id])
    result = conn.execute(sql)
    return jsonify({'images': [dict(row) for row in result]}), 200


@app.route('/memento/images/<int:image_id>', methods=['GET'])
@token_required
def get_image(image_id):
    conn = model.engine.connect()
    sql = sqla.select([model.images.c.image_id, model.images.c.name, model.images.c.uri, model.images.c.type, model.images.c.resolution, model.images.c.project_id, model.images.c.owner_id]).where(
        model.images.c.image_id == image_id)
    result = conn.execute(sql)
    if result.rowcount == 0:
        abort(404)
    return jsonify({'image': dict(row) for row in result}), 200


@app.route('/memento/images', methods=['POST'])
@token_required
def create_image():
    if not request.json or not 'filepath' in request.json or not 'format' in request.json or not 'name' in request.json or not 'uri' in request.json or not 'type' in request.json or not 'project_id' in request.json or not 'owner_id' in request.json:
        abort(400)
    new_image = {
        'name': request.json['name'],
        'uri': request.json['uri'],
        'type': request.json['type'],
        'resolution': '',
        'project_id': request.json['project_id'],
        'owner_id': request.json['owner_id'],
    }
    conn = model.engine.connect()
    sql = model.images.insert().values(name=new_image['name'], uri=new_image['uri'], resolution=new_image['resolution'], type=new_image['type'], project_id=new_image['project_id'], owner_id=new_image['owner_id'])
    result = conn.execute(sql)
    new_image['image_id'] = result.inserted_primary_key[0]

    if (new_image['type'] == '' or new_image['type'] == 'T'):
        new_image['uri'] = str(new_image['project_id']) + "_" + str(new_image['image_id'])

        format = request.json['format']
        extension = ".png"
        image = Image.open(request.json['filepath'])
        width, height = image.size
        resolution = str(width) + "x" + str(height)
        if (format == 3 or format == '3'):
            image = image.convert('RGBA')
            image.save(app.config['MEMENTO_FLASK_UPLOAD_FOLDER'] + new_image['uri'] + ".png")
        elif (format == 2 or format == '2'):
            image = image.convert('RGBA')
            if (width > 3000 or height > 3000):
                image.thumbnail((3000, 3000))
                width, height = image.size
                resolution = str(width) + "x" + str(height)
            image.save(app.config['MEMENTO_FLASK_UPLOAD_FOLDER'] + new_image['uri'] + ".png")
        elif (format == 1 or format == '1'):
            image = image.convert('RGB')
            if (width > 3000 or height > 3000):
                image.thumbnail((3000, 3000))
                width, height = image.size
                resolution = str(width) + "x" + str(height)
            image.save(app.config['MEMENTO_FLASK_UPLOAD_FOLDER'] + new_image['uri'] + ".jpg", 'JPEG')
            extension = ".jpg"

        if (new_image['type'] == 'T'):
            if (format == 5 or format == '5'):
                image = image.convert('RGBA')
            elif (format == 4 or format == '4'):
                image = image.convert('RGB')
                extension = ".jpg"

            z_levels = int(max(width / 1024 + (1 if width % 1024 > 0 else 0),
                           height / 1024 + (1 if height % 1024 > 0 else 0)))
            for i in range(8):
                if z_levels <= pow(2, i):
                    z_levels = i
                    break
            for curr_z_level in range(1, z_levels + 1, 1):
                z_dim = 1024 * pow(2, (curr_z_level - 1))

                width_tiles = int(width / z_dim) + (1 if width % z_dim > 0 else 0)
                height_tiles = int(height / z_dim) + (1 if height % z_dim > 0 else 0)
                for i in range(width_tiles):
                    for j in range(height_tiles):
                        x_crop = z_dim * i
                        y_crop = z_dim * j
                        im_crop = image.crop((x_crop, y_crop, x_crop + z_dim, y_crop + z_dim))
                        image_name = new_image['uri'] + '_z' + str(z_dim) + '_x' + str(x_crop) + '_y' + str(
                            y_crop) + extension
                        im_crop.thumbnail((1024, 1024))
                        if (extension == ".jpg"):
                            im_crop.save(app.config['MEMENTO_FLASK_UPLOAD_FOLDER'] + image_name, 'JPEG')
                        else:
                            im_crop.save(app.config['MEMENTO_FLASK_UPLOAD_FOLDER'] + image_name)
                        #app.logger.error('minio image: ' + image_name)
                        client.fput_object(app.config['S3_BUCKET'], image_name,
                                           app.config['MEMENTO_FLASK_UPLOAD_FOLDER'] + image_name,
                                           content_type="image/" + extension[1:])
                        os.remove(app.config['MEMENTO_FLASK_UPLOAD_FOLDER'] + image_name)

            image.thumbnail((1024, 1024))
            if (format == 5 or format == '5'):
                image.save(app.config['MEMENTO_FLASK_UPLOAD_FOLDER'] + new_image['uri'] + ".png")
            elif (format == 4 or format == '4'):
                image.save(app.config['MEMENTO_FLASK_UPLOAD_FOLDER'] + new_image['uri'] + ".jpg", 'JPEG')

        image.thumbnail((128, 128))
        image.save(app.config['MEMENTO_FLASK_UPLOAD_FOLDER'] + new_image['uri'] + "_thumb.png")

        sql = model.images.update().values(uri=new_image['uri'] + extension, resolution=resolution).where(
            model.images.c.image_id == new_image['image_id'])
        conn.execute(sql)

        client.fput_object(app.config['S3_BUCKET'], new_image['uri'] + extension, app.config['MEMENTO_FLASK_UPLOAD_FOLDER'] + new_image['uri'] + extension, content_type="image/" + extension[1:])
        client.fput_object(app.config['S3_BUCKET'], new_image['uri'] + "_thumb.png", app.config['MEMENTO_FLASK_UPLOAD_FOLDER'] + new_image['uri'] + "_thumb.png", content_type="image/png")

        os.remove(app.config['MEMENTO_FLASK_UPLOAD_FOLDER'] + new_image['uri'] + extension)
        os.remove(app.config['MEMENTO_FLASK_UPLOAD_FOLDER'] + new_image['uri'] + "_thumb.png")

    return jsonify({'image': new_image}), 201


@app.route('/memento/images/<int:image_id>', methods=['PUT'])
@token_required
def update_image(image_id):
    if not request.json or not 'name' in request.json or not 'uri' in request.json or not 'type' in request.json or not 'resolution' in request.json or not 'project_id' in request.json or not 'owner_id' in request.json:
        abort(400)
    updated_image = {
        'image_id': image_id,
        'name': request.json['name'],
        'uri': request.json['uri'],
        'type': request.json['type'],
        'resolution': request.json['resolution'],
        'project_id': request.json['project_id'],
        'owner_id': request.json['owner_id'],
    }
    conn = model.engine.connect()
    sql = model.images.update().values(name=updated_image['name'], uri=updated_image['uri'], type=updated_image['type'], resolution=updated_image['resolution'], project_id=updated_image['project_id'], owner_id=updated_image['owner_id']). \
        where(model.images.c.image_id == image_id)
    conn.execute(sql)
    return jsonify({'image': updated_image}), 201


@app.route('/memento/images/<int:image_id>', methods=['DELETE'])
@token_required
def delete_image(image_id):
    conn = model.engine.connect()

    sql = sqla.select([model.images.c.image_id, model.images.c.name, model.images.c.uri, model.images.c.type, model.images.c.resolution, model.images.c.project_id, model.images.c.owner_id]).where(
        model.images.c.image_id == image_id)
    result = conn.execute(sql)
    if result.rowcount == 0:
        abort(404)

    image_uri = ''
    image_type = ''
    image_resolution = ''
    for row in result:
        image_uri = row['uri']
        image_type = row['type']
        image_resolution = row['resolution']

    if (image_type == '' or image_type == 'T'):
        if (image_type == 'T'):
            extension = image_uri[-4:]
            width = int(image_resolution.split("x")[0])
            height = int(image_resolution.split("x")[1])
            z_levels = int(max(width / 1024 + (1 if width % 1024 > 0 else 0), height / 1024 + (1 if height % 1024 > 0 else 0)))
            for i in range(8):
                if z_levels <= pow(2, i):
                    z_levels = i
                    break
            for curr_z_level in range(1, z_levels + 1, 1):
                z_dim = 1024 * pow(2, (curr_z_level - 1))

                width_tiles = int(width / z_dim) + (1 if width % z_dim > 0 else 0)
                height_tiles = int(height / z_dim) + (1 if height % z_dim > 0 else 0)
                for i in range(width_tiles):
                    for j in range(height_tiles):
                        x_crop = z_dim * i
                        y_crop = z_dim * j
                        image_name = image_uri[:-4] + '_z' + str(z_dim) + '_x' + str(x_crop) + '_y' + str(y_crop) + extension
                        app.logger.error('minio image deleted: ' + image_name)
                        client.remove_object(app.config['S3_BUCKET'], image_name)

    sql = model.images.delete().where(model.images.c.image_id == image_id)
    conn.execute(sql)
    return "", 204


@app.route('/memento/images/geturl/<int:image_id>/<int:thumb>/<string:sub_filename>', methods=['GET'])
@token_required
def get_image_url(image_id, thumb, sub_filename):
    conn = model.engine.connect()
    sql = sqla.select([model.images.c.image_id, model.images.c.name, model.images.c.uri, model.images.c.type, model.images.c.resolution, model.images.c.project_id, model.images.c.owner_id]).where(
        model.images.c.image_id == image_id)
    result = conn.execute(sql)
    if result.rowcount == 0:
        abort(404)

    image_uri = ''
    for row in result:
        image_uri = row['uri']
    if (thumb == 1):
        image_uri = image_uri[:-4] + '_thumb.png'
    elif (sub_filename != "none"):
        image_uri = sub_filename

    presignedUrl = client.presigned_get_object(app.config['S3_BUCKET'], image_uri, expires=timedelta(hours=2))
    return jsonify({'url': presignedUrl}), 200


@app.route('/memento/images/byproject_id/<int:project_id>', methods=['GET'])
@token_required
def get_image_byproject_id(project_id):
    conn = model.engine.connect()
    sql = sqla.select([model.images.c.image_id, model.images.c.name, model.images.c.uri, model.images.c.type, model.images.c.resolution, model.images.c.project_id, model.images.c.owner_id]).where(
        model.images.c.project_id == project_id)
    result = conn.execute(sql)
    if result.rowcount == 0:
        abort(404)
    return jsonify({'images': [dict(row) for row in result]}), 200


@app.route('/memento/images/upload', methods=['POST'])
@token_required
def upload_file():
    json_data = eval(request.form['json'])

    if 'file' not in request.files or not json_data or not 'name' in json_data or not 'format' in json_data or not 'type' in json_data or not 'project_id' in json_data or not 'owner_id' in json_data:
        abort(400)

    new_image = {
        'name': json_data['name'],
        'type': json_data['type'],
        'resolution': '',
        'project_id': json_data['project_id'],
        'owner_id': json_data['owner_id'],
    }

    file = request.files['file']
    if new_image['type'] == '':
        if file.filename == '':
            abort(400)

        filename = secure_filename(file.filename)

        file.save(os.path.join(app.config['MEMENTO_FLASK_UPLOAD_FOLDER'], filename))

        new_image['uri'] = 'temp'
    else:
        if 'uri' not in json_data:
            abort(400)

        new_image['uri'] = json_data['uri']

    conn = model.engine.connect()
    sql = model.images.insert().values(name=new_image['name'], uri=new_image['uri'], type=new_image['type'], resolution=new_image['resolution'], project_id=new_image['project_id'], owner_id=new_image['owner_id'])
    result = conn.execute(sql)
    new_image['image_id'] = result.inserted_primary_key[0]

    if new_image['type'] == '' or new_image['type'] == 'T':
        new_image['uri'] = str(new_image['project_id']) + "_" + str(new_image['image_id'])

        format = json_data['format']
        extension = ".png"
        image = Image.open(os.path.join(app.config['MEMENTO_FLASK_UPLOAD_FOLDER'], filename))
        width, height = image.size
        resolution = str(width) + "x" + str(height)
        if (format == 3 or format == '3'):
            image = image.convert('RGBA')
            image.save(app.config['MEMENTO_FLASK_UPLOAD_FOLDER'] + new_image['uri'] + ".png")
        elif (format == 2 or format == '2'):
            image = image.convert('RGBA')
            if (width > 3000 or height > 3000):
                image.thumbnail((3000, 3000))
                width, height = image.size
                resolution = str(width) + "x" + str(height)
            image.save(app.config['MEMENTO_FLASK_UPLOAD_FOLDER'] + new_image['uri'] + ".png")
        elif (format == 1 or format == '1'):
            image = image.convert('RGB')
            if (width > 3000 or height > 3000):
                image.thumbnail((3000, 3000))
                width, height = image.size
                resolution = str(width) + "x" + str(height)
            image.save(app.config['MEMENTO_FLASK_UPLOAD_FOLDER'] + new_image['uri'] + ".jpg", 'JPEG')
            extension = ".jpg"

        if (new_image['type'] == 'T'):
            if (format == 5 or format == '5'):
                image = image.convert('RGBA')
            elif (format == 4 or format == '4'):
                image = image.convert('RGB')
                extension = ".jpg"

            z_levels = int(max(width / 1024 + (1 if width % 1024 > 0 else 0),
                           height / 1024 + (1 if height % 1024 > 0 else 0)))
            for i in range(8):
                if z_levels <= pow(2, i):
                    z_levels = i
                    break
            for curr_z_level in range(1, z_levels + 1, 1):
                z_dim = 1024 * pow(2, (curr_z_level - 1))

                width_tiles = int(width / z_dim) + (1 if width % z_dim > 0 else 0)
                height_tiles = int(height / z_dim) + (1 if height % z_dim > 0 else 0)
                for i in range(width_tiles):
                    for j in range(height_tiles):
                        x_crop = z_dim * i
                        y_crop = z_dim * j
                        im_crop = image.crop((x_crop, y_crop, x_crop + z_dim, y_crop + z_dim))
                        image_name = new_image['uri'] + '_z' + str(z_dim) + '_x' + str(x_crop) + '_y' + str(
                            y_crop) + extension
                        im_crop.thumbnail((1024, 1024))
                        if (extension == ".jpg"):
                            im_crop.save(app.config['MEMENTO_FLASK_UPLOAD_FOLDER'] + image_name, 'JPEG')
                        else:
                            im_crop.save(app.config['MEMENTO_FLASK_UPLOAD_FOLDER'] + image_name)
                        client.fput_object(app.config['S3_BUCKET'], image_name,
                                           app.config['MEMENTO_FLASK_UPLOAD_FOLDER'] + image_name,
                                           content_type="image/" + extension[1:])
                        os.remove(app.config['MEMENTO_FLASK_UPLOAD_FOLDER'] + image_name)

            image.thumbnail((1024, 1024))
            if (format == 5 or format == '5'):
                image.save(app.config['MEMENTO_FLASK_UPLOAD_FOLDER'] + new_image['uri'] + ".png")
            elif (format == 4 or format == '4'):
                image.save(app.config['MEMENTO_FLASK_UPLOAD_FOLDER'] + new_image['uri'] + ".jpg", 'JPEG')

        image.thumbnail((128, 128))
        image.save(app.config['MEMENTO_FLASK_UPLOAD_FOLDER'] + new_image['uri'] + "_thumb.png")

        sql = model.images.update().values(uri=new_image['uri'] + extension, resolution=resolution).where(
            model.images.c.image_id == new_image['image_id'])
        conn.execute(sql)

        client.fput_object(app.config['S3_BUCKET'], new_image['uri'] + extension, app.config['MEMENTO_FLASK_UPLOAD_FOLDER'] + new_image['uri'] + extension, content_type="image/" + extension[1:])
        client.fput_object(app.config['S3_BUCKET'], new_image['uri'] + "_thumb.png", app.config['MEMENTO_FLASK_UPLOAD_FOLDER'] + new_image['uri'] + "_thumb.png", content_type="image/png")

        if (filename != new_image['uri'] + extension):
            os.remove(app.config['MEMENTO_FLASK_UPLOAD_FOLDER'] + filename)
        os.remove(app.config['MEMENTO_FLASK_UPLOAD_FOLDER'] + new_image['uri'] + extension)
        os.remove(app.config['MEMENTO_FLASK_UPLOAD_FOLDER'] + new_image['uri'] + "_thumb.png")

    return jsonify({'image': new_image}), 201


@app.route('/memento/annotations', methods=['GET'])
@token_required
def get_annotations():
    conn = model.engine.connect()
    sql = sqla.select([model.annotations.c.annotation_id, model.annotations.c.name, model.annotations.c.status, model.annotations.c.shared, model.annotations.c.image_id,
                       model.annotations.c.project_id, model.annotations.c.category_id, model.annotations.c.owner_id])
    result = conn.execute(sql)
    return jsonify({'annotations': [dict(row) for row in result]}), 200


@app.route('/memento/annotations/<int:annotation_id>', methods=['GET'])
@token_required
def get_annotation(annotation_id):
    conn = model.engine.connect()
    sql = sqla.select([model.annotations.c.annotation_id, model.annotations.c.name, model.annotations.c.status, model.annotations.c.shared, model.annotations.c.image_id,
                       model.annotations.c.project_id, model.annotations.c.category_id, model.annotations.c.owner_id]).where(
        model.annotations.c.annotation_id == annotation_id)
    result = conn.execute(sql)
    if result.rowcount == 0:
        abort(404)
    return jsonify({'annotation': dict(row) for row in result}), 200


@app.route('/memento/annotations', methods=['POST'])
@token_required
def create_annotation():
    if not request.json or not 'name' in request.json or not 'status' in request.json or not 'shared' in request.json or not 'image_id' in request.json or not 'project_id' in request.json or not 'category_id' in request.json or not 'owner_id' in request.json:
        abort(400)
    new_annotation = {
        'name': request.json['name'],
        'status': request.json['status'],
        'shared': request.json['shared'],
        'image_id': request.json['image_id'],
        'project_id': request.json['project_id'],
        'category_id': request.json['category_id'],
        'owner_id': request.json['owner_id'],
    }
    conn = model.engine.connect()
    sql = model.annotations.insert().values(name=new_annotation['name'], status=new_annotation['status'], shared=new_annotation['shared'], image_id=new_annotation['image_id'], project_id=new_annotation['project_id'], category_id=new_annotation['category_id'], owner_id=new_annotation['owner_id'])
    result = conn.execute(sql)
    new_annotation['annotation_id'] = result.inserted_primary_key[0]
    return jsonify({'annotation': new_annotation}), 201


@app.route('/memento/annotations/<int:annotation_id>', methods=['PUT'])
@token_required
def update_annotation(annotation_id):
    if not request.json or not 'name' in request.json or not 'status' in request.json or not 'shared' in request.json or not 'image_id' in request.json or not 'project_id' in request.json or not 'category_id' in request.json or not 'owner_id' in request.json:
        abort(400)
    updated_annotation = {
        'annotation_id': annotation_id,
        'name': request.json['name'],
        'status': request.json['status'],
        'shared': request.json['shared'],
        'image_id': request.json['image_id'],
        'project_id': request.json['project_id'],
        'category_id': request.json['category_id'],
        'owner_id': request.json['owner_id'],
    }
    conn = model.engine.connect()
    sql = model.annotations.update().values(name=updated_annotation['name'], status=updated_annotation['status'], shared=updated_annotation['shared'], image_id=updated_annotation['image_id'], project_id=updated_annotation['project_id'], category_id=updated_annotation['category_id'], owner_id=updated_annotation['owner_id']). \
        where(model.annotations.c.annotation_id == annotation_id)
    conn.execute(sql)
    return jsonify({'annotation': updated_annotation}), 201


@app.route('/memento/annotations/<int:annotation_id>', methods=['DELETE'])
@token_required
def delete_annotation(annotation_id):
    conn = model.engine.connect()
    sql = model.annotations.delete().where(model.annotations.c.annotation_id == annotation_id)
    conn.execute(sql)
    return "", 204


@app.route('/memento/annotations/byproject_id/<int:project_id>', methods=['GET'])
@token_required
def get_annotation_byproject_id(project_id):
    conn = model.engine.connect()
    sql = sqla.select([model.annotations.c.annotation_id, model.annotations.c.name, model.annotations.c.status, model.annotations.c.shared, model.annotations.c.image_id,
                       model.annotations.c.project_id, model.annotations.c.category_id, model.annotations.c.owner_id]).where(
        model.annotations.c.project_id == project_id)
    result = conn.execute(sql)
    if result.rowcount == 0:
        abort(404)
    return jsonify({'annotations': [dict(row) for row in result]}), 200


@app.route('/memento/annotations/bycategory_id/<int:category_id>', methods=['GET'])
@token_required
def get_annotation_bycategory_id(category_id):
    conn = model.engine.connect()
    sql = sqla.select([model.annotations.c.annotation_id, model.annotations.c.name, model.annotations.c.status, model.annotations.c.shared, model.annotations.c.image_id,
                       model.annotations.c.project_id, model.annotations.c.category_id, model.annotations.c.owner_id]).where(
        model.annotations.c.category_id == category_id)
    result = conn.execute(sql)
    if result.rowcount == 0:
        abort(404)
    return jsonify({'annotations': [dict(row) for row in result]}), 200


@app.route('/memento/annotations/byimage_id/<int:image_id>', methods=['GET'])
@token_required
def get_annotation_byimage_id(image_id):
    conn = model.engine.connect()
    sql = sqla.select([model.annotations.c.annotation_id, model.annotations.c.name, model.annotations.c.status, model.annotations.c.shared, model.annotations.c.image_id,
                       model.annotations.c.project_id, model.annotations.c.category_id, model.annotations.c.owner_id]).where(
        model.annotations.c.image_id == image_id)
    result = conn.execute(sql)
    if result.rowcount == 0:
        abort(404)
    return jsonify({'annotations': [dict(row) for row in result]}), 200


@app.route('/memento/annotations/next/<int:project_id>/<int:category_id>', methods=['GET'])
@token_required
def get_next_annotation(project_id, category_id):
    conn = model.engine.connect()

    sql = sqla.select([model.annotations.c.annotation_id, model.annotations.c.name, model.annotations.c.status, model.annotations.c.shared, model.annotations.c.image_id,
                       model.annotations.c.project_id, model.annotations.c.category_id, model.annotations.c.owner_id]).where(
        model.annotations.c.status == 'N')
    if (project_id > 0):
        sql = sql.where(model.annotations.c.project_id == project_id)
    if (category_id > 0):
        sql = sql.where(model.annotations.c.category_id == category_id)
    result = conn.execute(sql)
    if result.rowcount == 0:
        abort(404)

    return jsonify({'next': [dict(row) for row in result]}), 200


@app.route('/memento/annotations_labels', methods=['GET'])
@token_required
def get_annotations_labels():
    conn = model.engine.connect()
    sql = sqla.select([model.annotations_labels.c.annotation_id, model.annotations_labels.c.label_id])
    result = conn.execute(sql)
    return jsonify({'annotations_labels': [dict(row) for row in result]}), 200


@app.route('/memento/annotations_labels/<int:annotation_id>/<int:label_id>', methods=['GET'])
@token_required
def get_annotation_label(annotation_id, label_id):
    conn = model.engine.connect()
    sql = sqla.select([model.annotations_labels.c.annotation_id, model.annotations_labels.c.label_id]).where(
        model.annotations_labels.c.annotation_id == annotation_id).where(
        model.annotations_labels.c.label_id == label_id)
    result = conn.execute(sql)
    if result.rowcount == 0:
        abort(404)
    return jsonify({'annotation_label': dict(row) for row in result}), 200


@app.route('/memento/annotations_labels', methods=['POST'])
@token_required
def create_annotation_label():
    if not request.json or not 'annotation_id' in request.json or not 'label_id' in request.json:
        abort(400)
    new_annotation_label = {
        'annotation_id': request.json['annotation_id'],
        'label_id': request.json['label_id'],
    }
    conn = model.engine.connect()
    sql = model.annotations_labels.insert().values(annotation_id=new_annotation_label['annotation_id'], label_id=new_annotation_label['label_id'])
    result = conn.execute(sql)
    return jsonify({'annotation_label': new_annotation_label}), 201


@app.route('/memento/annotations_labels/<int:annotation_id>/<int:label_id>', methods=['DELETE'])
@token_required
def delete_annotation_label(annotation_id, label_id):
    conn = model.engine.connect()
    sql = model.annotations_labels.delete().where(model.annotations_labels.c.annotation_id == annotation_id).where(
        model.annotations_labels.c.label_id == label_id)
    conn.execute(sql)
    return "", 204


@app.route('/memento/annotations_labels/byfilter/<int:annotation_id>/<int:label_id>', methods=['GET'])
@token_required
def get_annotations_labels_byfilter(annotation_id, label_id):
    conn = model.engine.connect()
    sql = sqla.select([model.annotations_labels.c.annotation_id, model.annotations_labels.c.label_id])
    if (annotation_id > 0):
        sql = sql.where(model.annotations_labels.c.annotation_id == annotation_id)
    if (label_id > 0):
        sql = sql.where(model.annotations_labels.c.label_id == label_id)
    result = conn.execute(sql)
    return jsonify({'annotations_labels': [dict(row) for row in result]}), 200


@app.route('/memento/annotations_labels/byfilter/<int:annotation_id>/<int:label_id>', methods=['DELETE'])
@token_required
def delete_annotations_labels_byfilter(annotation_id, label_id):
    conn = model.engine.connect()
    sql = model.annotations_labels.delete()
    if (annotation_id > 0):
        sql = sql.where(model.annotations_labels.c.annotation_id == annotation_id)
    if (label_id > 0):
        sql = sql.where(model.annotations_labels.c.label_id == label_id)
    conn.execute(sql)
    return "", 204


@app.route('/memento/layers', methods=['GET'])
@token_required
def get_layers():
    conn = model.engine.connect()
    sql = sqla.select([model.layers.c.layer_id, model.layers.c.name, model.layers.c.data, model.layers.c.image_id, model.layers.c.sequence, model.layers.c.parent_id, model.layers.c.annotation_id, model.layers.c.owner_id])
    result = conn.execute(sql)
    return jsonify({'layers': [dict(row) for row in result]}), 200


@app.route('/memento/layers/<int:layer_id>', methods=['GET'])
@token_required
def get_layer(layer_id):
    conn = model.engine.connect()
    sql = sqla.select([model.layers.c.layer_id, model.layers.c.name, model.layers.c.data, model.layers.c.image_id, model.layers.c.sequence, model.layers.c.parent_id, model.layers.c.annotation_id, model.layers.c.owner_id]).where(
        model.layers.c.layer_id == layer_id)
    result = conn.execute(sql)
    if result.rowcount == 0:
        abort(404)
    return jsonify({'layer': dict(row) for row in result}), 200


@app.route('/memento/layers', methods=['POST'])
@token_required
def create_layer():
    if not request.json or not 'name' in request.json or not 'data' in request.json or not 'image_id' in request.json or not 'sequence' in request.json or not 'parent_id' in request.json or not 'annotation_id' in request.json or not 'owner_id' in request.json:
        abort(400)
    new_layer = {
        'name': request.json['name'],
        'data': request.json['data'],
        'image_id': request.json['image_id'],
        'sequence': request.json['sequence'],
        'parent_id': request.json['parent_id'],
        'annotation_id': request.json['annotation_id'],
        'owner_id': request.json['owner_id'],
    }
    conn = model.engine.connect()
    sql = model.layers.insert().values(name=new_layer['name'], data=new_layer['data'], image_id=new_layer['image_id'], sequence=new_layer['sequence'], parent_id=new_layer['parent_id'], annotation_id=new_layer['annotation_id'], owner_id=new_layer['owner_id'])
    result = conn.execute(sql)
    new_layer['layer_id'] = result.inserted_primary_key[0]
    return jsonify({'layer': new_layer}), 201


@app.route('/memento/layers/<int:layer_id>', methods=['PUT'])
@token_required
def update_layer(layer_id):
    if not request.json or not 'name' in request.json or not 'data' in request.json or not 'image_id' in request.json or not 'sequence' in request.json or not 'parent_id' in request.json or not 'annotation_id' in request.json or not 'owner_id' in request.json:
        abort(400)
    updated_layer = {
        'layer_id': layer_id,
        'name': request.json['name'],
        'data': request.json['data'],
        'image_id': request.json['image_id'],
        'sequence': request.json['sequence'],
        'parent_id': request.json['parent_id'],
        'annotation_id': request.json['annotation_id'],
        'owner_id': request.json['owner_id'],
    }
    conn = model.engine.connect()
    sql = model.layers.update().values(name=updated_layer['name'], data=updated_layer['data'], image_id=updated_layer['image_id'], sequence=updated_layer['sequence'], parent_id=updated_layer['parent_id'], annotation_id=updated_layer['annotation_id'], owner_id=updated_layer['owner_id']). \
        where(model.layers.c.layer_id == layer_id)
    conn.execute(sql)
    return jsonify({'layer': updated_layer}), 201


@app.route('/memento/layers/<int:layer_id>', methods=['DELETE'])
@token_required
def delete_layer(layer_id):
    conn = model.engine.connect()
    sql = model.layers.delete().where(model.layers.c.layer_id == layer_id)
    conn.execute(sql)
    return "", 204


@app.route('/memento/layers/byannotation_id/<int:annotation_id>', methods=['GET'])
@token_required
def get_layers_byannotation_id(annotation_id):
    conn = model.engine.connect()
    sql = sqla.select([model.layers.c.layer_id, model.layers.c.name, model.layers.c.data, model.layers.c.image_id, model.layers.c.sequence, model.layers.c.parent_id, model.layers.c.annotation_id, model.layers.c.owner_id]).where(
        model.layers.c.annotation_id == annotation_id).order_by(model.layers.c.sequence.asc())
    result = conn.execute(sql)
    if result.rowcount == 0:
        abort(404)
    return jsonify({'layers': [dict(row) for row in result]}), 200


@app.route('/memento/layers/byimage_id/<int:image_id>', methods=['GET'])
@token_required
def get_layers_byimage_id(image_id):
    conn = model.engine.connect()
    sql = sqla.select([model.layers.c.layer_id, model.layers.c.name, model.layers.c.data, model.layers.c.image_id, model.layers.c.sequence, model.layers.c.parent_id, model.layers.c.annotation_id, model.layers.c.owner_id]).where(
        model.layers.c.image_id == image_id).order_by(model.layers.c.sequence.asc())
    result = conn.execute(sql)
    if result.rowcount == 0:
        abort(404)
    return jsonify({'layers': [dict(row) for row in result]}), 200


@app.route('/memento/layers/byfilter/<int:annotation_id>/<int:sequence>', methods=['GET'])
@token_required
def get_layers_byfilter(annotation_id, sequence):
    conn = model.engine.connect()
    sql = sqla.select([model.layers.c.layer_id, model.layers.c.name, model.layers.c.data, model.layers.c.image_id, model.layers.c.sequence, model.layers.c.parent_id, model.layers.c.annotation_id, model.layers.c.owner_id])
    if (annotation_id > 0):
        sql = sql.where(model.layers.c.annotation_id == annotation_id).order_by(model.layers.c.sequence.asc())
    if (sequence > 0):
        sql = sql.where(model.layers.c.sequence == sequence)
    result = conn.execute(sql)
    return jsonify({'layers': [dict(row) for row in result]}), 200


@app.route('/memento/comments', methods=['GET'])
@token_required
def get_comments():
    conn = model.engine.connect()
    sql = sqla.select([model.comments.c.comment_id, model.comments.c.content, model.comments.c.sequence, model.comments.c.layer_id, model.comments.c.owner_id])
    result = conn.execute(sql)
    return jsonify({'comments': [dict(row) for row in result]}), 200


@app.route('/memento/comments/<int:comment_id>', methods=['GET'])
@token_required
def get_comment(comment_id):
    conn = model.engine.connect()
    sql = sqla.select([model.comments.c.comment_id, model.comments.c.content, model.comments.c.sequence, model.comments.c.layer_id, model.comments.c.owner_id]).where(
        model.comments.c.comment_id == comment_id)
    result = conn.execute(sql)
    if result.rowcount == 0:
        abort(404)
    return jsonify({'comment': dict(row) for row in result}), 200


@app.route('/memento/comments', methods=['POST'])
@token_required
def create_comment():
    if not request.json or not 'content' in request.json or not 'sequence' in request.json or not 'layer_id' in request.json or not 'owner_id' in request.json:
        abort(400)
    new_comment = {
        'content': request.json['content'],
        'sequence': request.json['sequence'],
        'layer_id': request.json['layer_id'],
        'owner_id': request.json['owner_id'],
    }
    conn = model.engine.connect()
    sql = model.comments.insert().values(content=new_comment['content'], sequence=new_comment['sequence'], layer_id=new_comment['layer_id'], owner_id=new_comment['owner_id'])
    result = conn.execute(sql)
    new_comment['comment_id'] = result.inserted_primary_key[0]
    return jsonify({'comment': new_comment}), 201


@app.route('/memento/comments/<int:comment_id>', methods=['PUT'])
@token_required
def update_comment(comment_id):
    if not request.json or not 'content' in request.json or not 'sequence' in request.json or not 'layer_id' in request.json or not 'owner_id' in request.json:
        abort(400)
    updated_comment = {
        'comment_id': comment_id,
        'content': request.json['content'],
        'sequence': request.json['sequence'],
        'layer_id': request.json['layer_id'],
        'owner_id': request.json['owner_id'],
    }
    conn = model.engine.connect()
    sql = model.comments.update().values(content=updated_comment['content'], sequence=updated_comment['sequence'], layer_id=updated_comment['layer_id'], owner_id=updated_comment['owner_id']). \
        where(model.comments.c.comment_id == comment_id)
    conn.execute(sql)
    return jsonify({'comment': updated_comment}), 201


@app.route('/memento/comments/<int:comment_id>', methods=['DELETE'])
@token_required
def delete_comment(comment_id):
    conn = model.engine.connect()
    sql = model.comments.delete().where(model.comments.c.comment_id == comment_id)
    conn.execute(sql)
    return "", 204


@app.route('/memento/comments/bylayer_id/<int:layer_id>', methods=['GET'])
@token_required
def get_comment_bylayer_id(layer_id):
    conn = model.engine.connect()
    sql = sqla.select([model.comments.c.comment_id, model.comments.c.content, model.comments.c.sequence, model.comments.c.layer_id, model.comments.c.owner_id]).where(
        model.comments.c.layer_id == layer_id).order_by(model.comments.c.sequence.asc())
    result = conn.execute(sql)
    if result.rowcount == 0:
        abort(404)
    return jsonify({'comments': [dict(row) for row in result]}), 200


@app.route('/memento/utilities/change_ownership/<int:old_owner_id>/<int:new_owner_id>', methods=['PUT'])
@token_required
def change_ownership(old_owner_id, new_owner_id):
    conn = model.engine.connect()
    sql = model.projects.update().values(owner_id=new_owner_id).where(model.projects.c.owner_id == old_owner_id)
    conn.execute(sql)
    sql = model.categories.update().values(owner_id=new_owner_id).where(model.categories.c.owner_id == old_owner_id)
    conn.execute(sql)
    sql = model.labels.update().values(owner_id=new_owner_id).where(model.labels.c.owner_id == old_owner_id)
    conn.execute(sql)
    sql = model.images.update().values(owner_id=new_owner_id).where(model.images.c.owner_id == old_owner_id)
    conn.execute(sql)
    sql = model.annotations.update().values(owner_id=new_owner_id).where(model.annotations.c.owner_id == old_owner_id)
    conn.execute(sql)
    return "", 201


@app.route('/memento/utilities/project_summary/<int:project_id>', methods=['GET'])
@token_required
def project_summary(project_id):
    conn = model.engine.connect()
    new_project_summary = {}

    total_participants = {}

    sql = sqla.select([model.permissions.c.user_id, model.permissions.c.type, model.permissions.c.type_id])
    result = conn.execute(sql)
    list_permissions = [dict(row) for row in result]
    for curr_per in list_permissions:
        if (total_participants.get(curr_per['user_id']) == None):
            if (curr_per['type'] == 'propar' and curr_per['type_id'] == project_id):
                total_participants[curr_per['user_id']] = 'pro'
            elif (curr_per['type'] == 'catpar'):
                sql = sqla.select([model.categories.c.project_id]).where(
                    model.categories.c.category_id == curr_per['type_id']).where(
                    model.categories.c.project_id == project_id)
                result = conn.execute(sql)
                if result.rowcount > 0:
                    total_participants[curr_per['user_id']] = 'cat'
            elif (curr_per['type'] == 'annpar'):
                sql = sqla.select([model.annotations.c.project_id]).where(
                    model.annotations.c.annotation_id == curr_per['type_id']).where(
                    model.annotations.c.project_id == project_id)
                result = conn.execute(sql)
                if result.rowcount > 0:
                    total_participants[curr_per['user_id']] = 'ann'

    new_project_summary['total_participants'] = len(total_participants)

    sql = sqla.select([model.annotations.c.annotation_id]).where(model.annotations.c.project_id == project_id)
    result = conn.execute(sql)
    new_project_summary['total_annotations'] = result.rowcount

    sql = sqla.select([model.annotations.c.annotation_id]).where(model.annotations.c.project_id == project_id).where(
        model.annotations.c.status == 'S')
    result = conn.execute(sql)
    new_project_summary['total_annotations_submitted'] = result.rowcount

    sql = sqla.select([model.annotations.c.annotation_id]).where(model.annotations.c.project_id == project_id).where(
        model.annotations.c.shared != '')
    result = conn.execute(sql)
    new_project_summary['total_annotations_shared'] = result.rowcount

    return jsonify(new_project_summary), 200


@app.route('/memento/utilities/project_data/<int:project_id>', methods=['GET'])
@token_required
def project_data(project_id):
    conn = model.engine.connect()

    result = conn.execute('select pro.name as c1, cat.name as c2, cla.name as c3, ann.name as c4, img.name as c5, ann.status as c6, lab.name as c7, img.uri as c8 from projects pro, images img, categories cat left outer join categories_classifications catcla on cat.category_id=catcla.category_id left outer join classifications cla on catcla.classification_id=cla.classification_id, annotations ann left outer join annotations_labels annlab on ann.annotation_id=annlab.annotation_id left outer join labels lab on annlab.label_id=lab.label_id where ann.project_id=pro.project_id and ann.category_id=cat.category_id and ann.image_id=img.image_id and ann.project_id=%s', project_id)
    return jsonify({'project_data': [dict(row) for row in result]}), 200


@app.route('/memento/utilities/project_comments/<int:project_id>', methods=['GET'])
@token_required
def project_comments(project_id):
    conn = model.engine.connect()

    result = conn.execute('select pro.name as c1, cat.name as c2, ann.name as c3, lay.name as c4, com.content as c5 from projects pro, categories cat, annotations ann, layers lay, comments com where ann.project_id=pro.project_id and ann.category_id=cat.category_id and ann.annotation_id=lay.annotation_id and lay.layer_id=com.layer_id and pro.project_id=%s', project_id)
    return jsonify({'project_comments': [dict(row) for row in result]}), 200


@app.route('/memento/utilities/project_rois/<int:project_id>', methods=['GET'])
@token_required
def project_rois(project_id):
    conn = model.engine.connect()

    result = conn.execute('select pro.name as c1, cat.name as c2, ann.name as c3, lay.name as c4, lay.data as c5 from projects pro, categories cat, annotations ann, layers lay where ann.project_id=pro.project_id and ann.category_id=cat.category_id and ann.annotation_id=lay.annotation_id and pro.project_id=%s', project_id)
    return jsonify({'project_rois': [dict(row) for row in result]}), 200


if __name__ == '__main__':
   app.run()
