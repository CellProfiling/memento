from flask import Flask, jsonify, request, abort, url_for, send_file, g
from werkzeug.utils import secure_filename
from werkzeug.exceptions import HTTPException
import jwt
import time
from datetime import timedelta
from functools import wraps
import logging
import model
import json
import os
import shutil
import PIL
from PIL import Image, ImageFile
import sqlalchemy as sqla
from itsdangerous import URLSafeTimedSerializer


app = Flask(__name__)

app.config['MEMENTO_FLASK_AUTH_TOKEN_KEY'] = os.environ.get("MEMENTO_FLASK_AUTH_TOKEN_KEY")
app.config['MEMENTO_FLASK_WHITE_LISTED_TOKEN'] = os.environ.get("MEMENTO_FLASK_WHITE_LISTED_TOKEN")
app.config['MEMENTO_FLASK_UPLOAD_FOLDER'] = "/opt/memento/upload/"
app.config['MEMENTO_FLASK_IMAGE_FOLDER'] = "/opt/memento/images/"

serializer = URLSafeTimedSerializer(app.config['MEMENTO_FLASK_AUTH_TOKEN_KEY'], salt='memento_flask')

gunicorn_logger = logging.getLogger('gunicorn.error')
app.logger.handlers = gunicorn_logger.handlers
app.logger.setLevel(gunicorn_logger.level)

ImageFile.LOAD_TRUNCATED_IMAGES = True
PIL.Image.MAX_IMAGE_PIXELS = 100000 * 100000  # support up to 100k x 100k px pyramidal images


def get_conn():
    if 'conn' not in g:
        g.conn = model.engine.connect()
    return g.conn


@app.teardown_request
def close_conn(exception):
    conn = g.pop('conn', None)
    if conn is not None:
        conn.close()


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
            data = jwt.decode(token, app.config['MEMENTO_FLASK_AUTH_TOKEN_KEY'], algorithms=['HS256'])
            if int(data['exp']) != 0 and time.time() > int(data['exp']):
                abort(401)
            conn = get_conn()
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
    conn = get_conn()
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
    conn = get_conn()
    sql = sqla.select([model.users.c.user_id, model.users.c.username, model.users.c.name, model.users.c.email, model.users.c.settings]).order_by(model.users.c.username.asc())
    result = conn.execute(sql)
    return jsonify({'users': [dict(row) for row in result]}), 200


@app.route('/memento/users/<int:user_id>', methods=['GET'])
@token_required
def get_user(user_id):
    conn = get_conn()
    sql = sqla.select([model.users.c.user_id, model.users.c.username, model.users.c.name, model.users.c.email, model.users.c.settings]).where(
        model.users.c.user_id == user_id)
    result = conn.execute(sql)
    if result.rowcount == 0:
        abort(404)
    return jsonify({'user': dict(result.first())}), 200


@app.route('/memento/users', methods=['POST'])
@token_required
def create_user():
    if not request.json or not 'username' in request.json or not 'name' in request.json or not 'email' in request.json or not 'password' in request.json or not 'settings' in request.json:
        abort(400)
    new_user = {
        'username': request.json['username'],
        'name': request.json['name'],
        'email': request.json['email'],
        'settings': request.json['settings'],
    }
    conn = get_conn()
    sql = model.users.insert().values(username=new_user['username'], name=new_user['name'], email=new_user['email'], settings=new_user['settings'],
                                      password=request.json['password'])
    result = conn.execute(sql)
    new_user['user_id'] = result.inserted_primary_key[0]
    return jsonify({'user': new_user}), 201


@app.route('/memento/users/<int:user_id>', methods=['PUT'])
@token_required
def update_user(user_id):
    if not request.json or not 'username' in request.json or not 'name' in request.json or not 'email' in request.json or not 'settings' in request.json:
        abort(400)
    updated_user = {
        'user_id': user_id,
        'username': request.json['username'],
        'name': request.json['name'],
        'email': request.json['email'],
        'settings': request.json['settings'],
    }
    conn = get_conn()
    update_vals = dict(username=updated_user['username'], name=updated_user['name'],
                       email=updated_user['email'], settings=updated_user['settings'])
    if request.json.get('password'):
        update_vals['password'] = request.json['password']
    sql = model.users.update().values(**update_vals).where(model.users.c.user_id == user_id)
    conn.execute(sql)
    return jsonify({'user': updated_user}), 201


@app.route('/memento/users/<int:user_id>', methods=['DELETE'])
@token_required
def delete_user(user_id):
    conn = get_conn()
    sql = model.users.delete().where(model.users.c.user_id == user_id)
    conn.execute(sql)
    return "", 204


@app.route('/memento/users/byusername/<string:username>', methods=['GET'])
@token_required
def get_user_byusername(username):
    conn = get_conn()
    sql = sqla.select([model.users.c.user_id, model.users.c.username, model.users.c.name, model.users.c.email, model.users.c.settings]). \
        where(model.users.c.username == username)
    result = conn.execute(sql)
    if result.rowcount == 0:
        abort(404)
    return jsonify({'user': dict(result.first())}), 200


@app.route('/memento/permissions', methods=['GET'])
@token_required
def get_permissions():
    conn = get_conn()
    sql = sqla.select([model.permissions.c.user_id, model.permissions.c.type, model.permissions.c.type_id]).order_by(model.permissions.c.user_id.asc())
    result = conn.execute(sql)
    return jsonify({'permissions': [dict(row) for row in result]}), 200


@app.route('/memento/permissions/<int:user_id>/<string:stype>/<int:type_id>', methods=['GET'])
@token_required
def get_permission(user_id, stype, type_id):
    conn = get_conn()
    sql = sqla.select([model.permissions.c.user_id, model.permissions.c.type, model.permissions.c.type_id]).where(
        model.permissions.c.user_id == user_id).where(model.permissions.c.type == stype).where(
        model.permissions.c.type_id == type_id)
    result = conn.execute(sql)
    if result.rowcount == 0:
        abort(404)
    return jsonify({'permission': dict(result.first())}), 200


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
    conn = get_conn()
    sql = model.permissions.insert().values(user_id=new_permission['user_id'], type=new_permission['type'], type_id=new_permission['type_id'])
    result = conn.execute(sql)
    return jsonify({'permission': new_permission}), 201


@app.route('/memento/permissions/<int:user_id>/<string:stype>/<int:type_id>', methods=['DELETE'])
@token_required
def delete_permission(user_id, stype, type_id):
    conn = get_conn()
    sql = model.permissions.delete().where(model.permissions.c.user_id == user_id).where(
        model.permissions.c.type == stype).where(model.permissions.c.type_id == type_id)
    conn.execute(sql)
    return "", 204


@app.route('/memento/permissions/byfilter/<int:user_id>/<string:stype>/<int:type_id>', methods=['GET'])
@token_required
def get_permissions_byfilter(user_id, stype, type_id):
    conn = get_conn()
    sql = sqla.select([model.permissions.c.user_id, model.permissions.c.type, model.permissions.c.type_id]).order_by(model.permissions.c.user_id.asc())
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
    conn = get_conn()
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
    conn = get_conn()
    sql = sqla.select([model.projects.c.project_id, model.projects.c.name, model.projects.c.owner_id]).order_by(model.projects.c.name.asc())
    result = conn.execute(sql)
    return jsonify({'projects': [dict(row) for row in result]}), 200


@app.route('/memento/projects/<int:project_id>', methods=['GET'])
@token_required
def get_project(project_id):
    conn = get_conn()
    sql = sqla.select([model.projects.c.project_id, model.projects.c.name, model.projects.c.owner_id, model.projects.c.settings]).where(
        model.projects.c.project_id == project_id)
    result = conn.execute(sql)
    if result.rowcount == 0:
        abort(404)
    return jsonify({'project': dict(result.first())}), 200


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
    conn = get_conn()
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
    conn = get_conn()
    sql = model.projects.update().values(name=updated_project['name'], owner_id=updated_project['owner_id'], settings=updated_project['settings']). \
        where(model.projects.c.project_id == project_id)
    conn.execute(sql)
    return jsonify({'project': updated_project}), 201


@app.route('/memento/projects/<int:project_id>', methods=['DELETE'])
@token_required
def delete_project(project_id):
    conn = get_conn()
    sql = model.projects.delete().where(model.projects.c.project_id == project_id)
    conn.execute(sql)
    return "", 204

@app.route('/memento/categories', methods=['GET'])
@token_required
def get_categories():
    conn = get_conn()
    sql = sqla.select([model.categories.c.category_id, model.categories.c.name, model.categories.c.project_id, model.categories.c.owner_id, model.categories.c.settings]).order_by(model.categories.c.name.asc())
    result = conn.execute(sql)
    return jsonify({'categories': [dict(row) for row in result]}), 200


@app.route('/memento/categories/<int:category_id>', methods=['GET'])
@token_required
def get_category(category_id):
    conn = get_conn()
    sql = sqla.select([model.categories.c.category_id, model.categories.c.name, model.categories.c.project_id, model.categories.c.owner_id, model.categories.c.settings]).where(
        model.categories.c.category_id == category_id)
    result = conn.execute(sql)
    if result.rowcount == 0:
        abort(404)
    return jsonify({'category': dict(result.first())}), 200


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
    conn = get_conn()
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
    conn = get_conn()
    sql = model.categories.update().values(name=updated_category['name'], project_id=updated_category['project_id'], owner_id=updated_category['owner_id'], settings=updated_category['settings']). \
        where(model.categories.c.category_id == category_id)
    conn.execute(sql)
    return jsonify({'category': updated_category}), 201


@app.route('/memento/categories/<int:category_id>', methods=['DELETE'])
@token_required
def delete_category(category_id):
    conn = get_conn()
    sql = model.categories.delete().where(model.categories.c.category_id == category_id)
    conn.execute(sql)
    return "", 204


@app.route('/memento/categories/byproject_id/<int:project_id>', methods=['GET'])
@token_required
def get_category_byproject_id(project_id):
    conn = get_conn()
    sql = sqla.select([model.categories.c.category_id, model.categories.c.name, model.categories.c.project_id, model.categories.c.owner_id, model.categories.c.settings]).where(
        model.categories.c.project_id == project_id).order_by(model.categories.c.name.asc())
    result = conn.execute(sql)
    if result.rowcount == 0:
        abort(404)
    return jsonify({'categories': [dict(row) for row in result]}), 200


@app.route('/memento/classifications', methods=['GET'])
@token_required
def get_classifications():
    conn = get_conn()
    sql = sqla.select([model.classifications.c.classification_id, model.classifications.c.name, model.classifications.c.type, model.classifications.c.data,
                       model.classifications.c.project_id, model.classifications.c.owner_id, model.classifications.c.settings]).order_by(model.classifications.c.name.asc())
    result = conn.execute(sql)
    return jsonify({'classifications': [dict(row) for row in result]}), 200


@app.route('/memento/classifications/<int:classification_id>', methods=['GET'])
@token_required
def get_classification(classification_id):
    conn = get_conn()
    sql = sqla.select([model.classifications.c.classification_id, model.classifications.c.name, model.classifications.c.type, model.classifications.c.data,
                       model.classifications.c.project_id, model.classifications.c.owner_id, model.classifications.c.settings]).where(
        model.classifications.c.classification_id == classification_id)
    result = conn.execute(sql)
    if result.rowcount == 0:
        abort(404)
    return jsonify({'classification': dict(result.first())}), 200


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
    conn = get_conn()
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
    conn = get_conn()
    sql = model.classifications.update().values(name=updated_classification['name'], type=updated_classification['type'], data=updated_classification['data'], project_id=updated_classification['project_id'], owner_id=updated_classification['owner_id'], settings=updated_classification['settings']). \
        where(model.classifications.c.classification_id == classification_id)
    conn.execute(sql)
    return jsonify({'classification': updated_classification}), 201


@app.route('/memento/classifications/<int:classification_id>', methods=['DELETE'])
@token_required
def delete_classification(classification_id):
    conn = get_conn()
    sql = model.classifications.delete().where(model.classifications.c.classification_id == classification_id)
    conn.execute(sql)
    return "", 204


@app.route('/memento/classifications/byproject_id/<int:project_id>', methods=['GET'])
@token_required
def get_classification_byproject_id(project_id):
    conn = get_conn()
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
    conn = get_conn()
    sql = sqla.select([model.classifications.c.classification_id, model.classifications.c.name, model.classifications.c.type, model.classifications.c.data,
                       model.classifications.c.project_id, model.classifications.c.owner_id, model.classifications.c.settings]).where(
        model.classifications.c.classification_id == model.categories_classifications.c.classification_id).where(
        model.categories_classifications.c.category_id == category_id)
    result = conn.execute(sql)
    if result.rowcount == 0:
        abort(404)
    return jsonify({'classifications': [dict(row) for row in result]}), 200


@app.route('/memento/categories_classifications', methods=['GET'])
@token_required
def get_categories_classifications():
    conn = get_conn()
    sql = sqla.select([model.categories_classifications.c.category_id, model.categories_classifications.c.classification_id])
    result = conn.execute(sql)
    return jsonify({'categories_classifications': [dict(row) for row in result]}), 200


@app.route('/memento/categories_classifications/<int:category_id>/<int:classification_id>', methods=['GET'])
@token_required
def get_category_classification(category_id, classification_id):
    conn = get_conn()
    sql = sqla.select([model.categories_classifications.c.category_id, model.categories_classifications.c.classification_id]).where(
        model.categories_classifications.c.category_id == category_id).where(
        model.categories_classifications.c.classification_id == classification_id)
    result = conn.execute(sql)
    if result.rowcount == 0:
        abort(404)
    return jsonify({'category_classification': dict(result.first())}), 200


@app.route('/memento/categories_classifications', methods=['POST'])
@token_required
def create_category_classification():
    if not request.json or not 'category_id' in request.json or not 'classification_id' in request.json:
        abort(400)
    new_category_classification = {
        'category_id': request.json['category_id'],
        'classification_id': request.json['classification_id'],
    }
    conn = get_conn()
    sql = model.categories_classifications.insert().values(category_id=new_category_classification['category_id'], classification_id=new_category_classification['classification_id'])
    result = conn.execute(sql)
    return jsonify({'category_classification': new_category_classification}), 201


@app.route('/memento/categories_classifications/<int:category_id>/<int:classification_id>', methods=['DELETE'])
@token_required
def delete_category_classification(category_id, classification_id):
    conn = get_conn()
    sql = model.categories_classifications.delete().where(model.categories_classifications.c.category_id == category_id).where(
        model.categories_classifications.c.classification_id == classification_id)
    conn.execute(sql)
    return "", 204


@app.route('/memento/categories_classifications/byfilter/<int:category_id>/<int:classification_id>', methods=['GET'])
@token_required
def get_categories_classifications_byfilter(category_id, classification_id):
    conn = get_conn()
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
    conn = get_conn()
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
    conn = get_conn()
    sql = sqla.select([model.labels.c.label_id, model.labels.c.name, model.labels.c.project_id, model.labels.c.owner_id]).order_by(model.labels.c.name.asc())
    result = conn.execute(sql)
    return jsonify({'labels': [dict(row) for row in result]}), 200


@app.route('/memento/labels/<int:label_id>', methods=['GET'])
@token_required
def get_label(label_id):
    conn = get_conn()
    sql = sqla.select([model.labels.c.label_id, model.labels.c.name, model.labels.c.project_id, model.labels.c.owner_id]).where(
        model.labels.c.label_id == label_id)
    result = conn.execute(sql)
    if result.rowcount == 0:
        abort(404)
    return jsonify({'label': dict(result.first())}), 200


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
    conn = get_conn()
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
    conn = get_conn()
    sql = model.labels.update().values(name=updated_label['name'], project_id=updated_label['project_id'], owner_id=updated_label['owner_id']). \
        where(model.labels.c.label_id == label_id)
    conn.execute(sql)
    return jsonify({'label': updated_label}), 201


@app.route('/memento/labels/<int:label_id>', methods=['DELETE'])
@token_required
def delete_label(label_id):
    conn = get_conn()
    sql = model.labels.delete().where(model.labels.c.label_id == label_id)
    conn.execute(sql)
    return "", 204


@app.route('/memento/labels/byproject_id/<int:project_id>', methods=['GET'])
@token_required
def get_label_byproject_id(project_id):
    conn = get_conn()
    sql = sqla.select([model.labels.c.label_id, model.labels.c.name, model.labels.c.project_id, model.labels.c.owner_id]).where(
        model.labels.c.project_id == project_id).order_by(model.labels.c.name.asc())
    result = conn.execute(sql)
    if result.rowcount == 0:
        abort(404)
    return jsonify({'labels': [dict(row) for row in result]}), 200


@app.route('/memento/images', methods=['GET'])
@token_required
def get_images():
    conn = get_conn()
    sql = sqla.select([model.images.c.image_id, model.images.c.name, model.images.c.uri, model.images.c.type, model.images.c.resolution, model.images.c.project_id, model.images.c.owner_id]).order_by(model.images.c.name.asc())
    result = conn.execute(sql)
    return jsonify({'images': [dict(row) for row in result]}), 200


@app.route('/memento/images/<int:image_id>', methods=['GET'])
@token_required
def get_image(image_id):
    conn = get_conn()
    sql = sqla.select([model.images.c.image_id, model.images.c.name, model.images.c.uri, model.images.c.type, model.images.c.resolution, model.images.c.project_id, model.images.c.owner_id]).where(
        model.images.c.image_id == image_id)
    result = conn.execute(sql)
    if result.rowcount == 0:
        abort(404)
    return jsonify({'image': dict(result.first())}), 200


# Image types (stored in images.type):
#   ''  - Standard flat image, stored as a single JPEG or PNG file.
#   'T' - Tiled/pyramidal image, split into zoom-level tile files for large images.
#   'E'   - Remote image, external URI only; no file is stored on this server.
#
# Image formats (upload-time parameter, not stored):
#   1 - Standard: RGB JPEG, resized to a maximum of 2048x2048.
#   2 - Standard: RGBA PNG,  resized to a maximum of 2048x2048.
#   3 - Standard: RGBA PNG,  full original resolution (no resize).
#   4 - Tiled:    RGB JPEG tiles across all zoom levels.
#   5 - Tiled:    RGBA PNG  tiles across all zoom levels.
def _process_and_store_image(image, image_type, fmt, uri_base, conn, image_id):
    """Convert, tile, thumbnail, move files to the serving folder, and update the DB uri/resolution.
    Returns the final URI (uri_base + extension) stored in the DB."""
    fmt = str(fmt)
    upload_folder = app.config['MEMENTO_FLASK_UPLOAD_FOLDER']
    image_folder = app.config['MEMENTO_FLASK_IMAGE_FOLDER']
    extension = '.png'
    width, height = image.size
    resolution = f'{width}x{height}'

    if image_type == '':
        if fmt == '3':
            image = image.convert('RGBA')
        elif fmt == '2':
            image = image.convert('RGBA')
            if width > 2048 or height > 2048:
                image.thumbnail((2048, 2048))
                width, height = image.size
                resolution = f'{width}x{height}'
        elif fmt == '1':
            image = image.convert('RGB')
            if width > 2048 or height > 2048:
                image.thumbnail((2048, 2048))
                width, height = image.size
                resolution = f'{width}x{height}'
            extension = '.jpg'
        if extension == '.jpg':
            image.save(upload_folder + uri_base + extension, 'JPEG')
        else:
            image.save(upload_folder + uri_base + extension)

    elif image_type == 'T':
        if fmt == '5':
            image = image.convert('RGBA')
        elif fmt == '4':
            image = image.convert('RGB')
            extension = '.jpg'

        z_levels = int(max(
            width / 1024 + (1 if width % 1024 > 0 else 0),
            height / 1024 + (1 if height % 1024 > 0 else 0),
        ))
        for i in range(8):
            if z_levels <= pow(2, i):
                z_levels = i
                break
        for curr_z_level in range(1, z_levels + 1):
            z_dim = 1024 * pow(2, curr_z_level - 1)
            width_tiles = int(width / z_dim) + (1 if width % z_dim > 0 else 0)
            height_tiles = int(height / z_dim) + (1 if height % z_dim > 0 else 0)
            for i in range(width_tiles):
                for j in range(height_tiles):
                    x_crop, y_crop = z_dim * i, z_dim * j
                    im_crop = image.crop((x_crop, y_crop, x_crop + z_dim, y_crop + z_dim))
                    image_name = f'{uri_base}_z{z_dim}_x{x_crop}_y{y_crop}{extension}'
                    im_crop.thumbnail((1024, 1024))
                    if extension == '.jpg':
                        im_crop.save(upload_folder + image_name, 'JPEG')
                    else:
                        im_crop.save(upload_folder + image_name)
                    shutil.copyfile(upload_folder + image_name, image_folder + image_name)
                    os.remove(upload_folder + image_name)

        image.thumbnail((1024, 1024))
        if extension == '.jpg':
            image.save(upload_folder + uri_base + extension, 'JPEG')
        else:
            image.save(upload_folder + uri_base + extension)

    image.thumbnail((128, 128))
    image.save(upload_folder + uri_base + '_thumb.png')

    final_uri = uri_base + extension
    conn.execute(
        model.images.update()
        .values(uri=final_uri, resolution=resolution)
        .where(model.images.c.image_id == image_id)
    )
    shutil.copyfile(upload_folder + final_uri, image_folder + final_uri)
    shutil.copyfile(upload_folder + uri_base + '_thumb.png', image_folder + uri_base + '_thumb.png')
    os.remove(upload_folder + final_uri)
    os.remove(upload_folder + uri_base + '_thumb.png')

    return final_uri


@app.route('/memento/images', methods=['POST'])
@token_required
def create_image():
    required = ['format', 'name', 'uri', 'type', 'project_id', 'owner_id']
    if not request.json or any(k not in request.json for k in required):
        abort(400)
    if request.json['type'] in ('', 'T') and 'filepath' not in request.json:
        abort(400)
    new_image = {
        'name': request.json['name'],
        'uri': request.json['uri'],
        'type': request.json['type'],
        'resolution': '',
        'project_id': request.json['project_id'],
        'owner_id': request.json['owner_id'],
    }
    conn = get_conn()
    sql = model.images.insert().values(
        name=new_image['name'], uri=new_image['uri'], resolution=new_image['resolution'],
        type=new_image['type'], project_id=new_image['project_id'], owner_id=new_image['owner_id'],
    )
    result = conn.execute(sql)
    new_image['image_id'] = result.inserted_primary_key[0]

    if new_image['type'] in ('', 'T'):
        uri_base = f"{new_image['project_id']}_{new_image['image_id']}"
        image = Image.open(request.json['filepath'])
        new_image['uri'] = _process_and_store_image(
            image, new_image['type'], request.json['format'], uri_base, conn, new_image['image_id'],
        )

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
    conn = get_conn()
    sql = model.images.update().values(name=updated_image['name'], uri=updated_image['uri'], type=updated_image['type'], resolution=updated_image['resolution'], project_id=updated_image['project_id'], owner_id=updated_image['owner_id']). \
        where(model.images.c.image_id == image_id)
    conn.execute(sql)
    return jsonify({'image': updated_image}), 201


@app.route('/memento/images/<int:image_id>', methods=['DELETE'])
@token_required
def delete_image(image_id):
    conn = get_conn()

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
                        app.logger.error('image deleted: ' + image_name)
                        os.remove(app.config['MEMENTO_FLASK_IMAGE_FOLDER'] + image_name)

    sql = model.images.delete().where(model.images.c.image_id == image_id)
    conn.execute(sql)
    return "", 204


@app.route('/memento/images/geturl/<int:image_id>/<int:thumb>/<string:sub_filename>', methods=['GET'])
@token_required
def get_image_url(image_id, thumb, sub_filename):
    conn = get_conn()
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

    if os.path.exists(app.config['MEMENTO_FLASK_IMAGE_FOLDER'] + image_uri):
        return send_file(app.config['MEMENTO_FLASK_IMAGE_FOLDER'] + image_uri, mimetype='image/' + os.path.splitext(image_uri)[1][1:])
    else:
        abort(404)


@app.route('/memento/images/byproject_id/<int:project_id>', methods=['GET'])
@token_required
def get_image_byproject_id(project_id):
    conn = get_conn()
    sql = sqla.select([model.images.c.image_id, model.images.c.name, model.images.c.uri, model.images.c.type, model.images.c.resolution, model.images.c.project_id, model.images.c.owner_id]).where(
        model.images.c.project_id == project_id).order_by(model.images.c.name.asc())
    result = conn.execute(sql)
    if result.rowcount == 0:
        abort(404)
    return jsonify({'images': [dict(row) for row in result]}), 200


@app.route('/memento/images/upload', methods=['POST'])
@token_required
def upload_file():
    json_data = json.loads(request.form['json'])
    required = ['name', 'format', 'type', 'project_id', 'owner_id']
    if not json_data or any(k not in json_data for k in required):
        abort(400)

    new_image = {
        'name': json_data['name'],
        'type': json_data['type'],
        'resolution': '',
        'project_id': json_data['project_id'],
        'owner_id': json_data['owner_id'],
    }

    if new_image['type'] in ('', 'T'):
        if 'file' not in request.files or request.files['file'].filename == '':
            abort(400)
        file = request.files['file']
        filename = secure_filename(file.filename)
        filepath = os.path.join(app.config['MEMENTO_FLASK_UPLOAD_FOLDER'], filename)
        file.save(filepath)
        new_image['uri'] = 'temp'
    else:
        if 'uri' not in json_data:
            abort(400)
        new_image['uri'] = json_data['uri']

    conn = get_conn()
    sql = model.images.insert().values(
        name=new_image['name'], uri=new_image['uri'], type=new_image['type'],
        resolution=new_image['resolution'], project_id=new_image['project_id'], owner_id=new_image['owner_id'],
    )
    result = conn.execute(sql)
    new_image['image_id'] = result.inserted_primary_key[0]

    if new_image['type'] in ('', 'T'):
        uri_base = f"{new_image['project_id']}_{new_image['image_id']}"
        image = Image.open(filepath)
        new_image['uri'] = _process_and_store_image(
            image, new_image['type'], json_data['format'], uri_base, conn, new_image['image_id'],
        )
        if filepath != app.config['MEMENTO_FLASK_UPLOAD_FOLDER'] + new_image['uri']:
            os.remove(filepath)

    return jsonify({'image': new_image}), 201


@app.route('/memento/annotations', methods=['GET'])
@token_required
def get_annotations():
    conn = get_conn()
    sql = sqla.select([model.annotations.c.annotation_id, model.annotations.c.name, model.annotations.c.status, model.annotations.c.shared, model.annotations.c.image_id,
                       model.annotations.c.project_id, model.annotations.c.category_id, model.annotations.c.owner_id]).order_by(model.annotations.c.name.asc())
    result = conn.execute(sql)
    return jsonify({'annotations': [dict(row) for row in result]}), 200


@app.route('/memento/annotations/<int:annotation_id>', methods=['GET'])
@token_required
def get_annotation(annotation_id):
    conn = get_conn()
    sql = sqla.select([model.annotations.c.annotation_id, model.annotations.c.name, model.annotations.c.status, model.annotations.c.shared, model.annotations.c.image_id,
                       model.annotations.c.project_id, model.annotations.c.category_id, model.annotations.c.owner_id]).where(
        model.annotations.c.annotation_id == annotation_id)
    result = conn.execute(sql)
    if result.rowcount == 0:
        abort(404)
    return jsonify({'annotation': dict(result.first())}), 200


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
    conn = get_conn()
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
    conn = get_conn()
    sql = model.annotations.update().values(name=updated_annotation['name'], status=updated_annotation['status'], shared=updated_annotation['shared'], image_id=updated_annotation['image_id'], project_id=updated_annotation['project_id'], category_id=updated_annotation['category_id'], owner_id=updated_annotation['owner_id']). \
        where(model.annotations.c.annotation_id == annotation_id)
    conn.execute(sql)
    return jsonify({'annotation': updated_annotation}), 201


@app.route('/memento/annotations/<int:annotation_id>', methods=['DELETE'])
@token_required
def delete_annotation(annotation_id):
    conn = get_conn()
    sql = model.annotations.delete().where(model.annotations.c.annotation_id == annotation_id)
    conn.execute(sql)
    return "", 204


@app.route('/memento/annotations/byproject_id/<int:project_id>', methods=['GET'])
@token_required
def get_annotation_byproject_id(project_id):
    conn = get_conn()
    sql = sqla.select([model.annotations.c.annotation_id, model.annotations.c.name, model.annotations.c.status, model.annotations.c.shared, model.annotations.c.image_id,
                       model.annotations.c.project_id, model.annotations.c.category_id, model.annotations.c.owner_id]).where(
        model.annotations.c.project_id == project_id).order_by(model.annotations.c.name.asc())
    result = conn.execute(sql)
    if result.rowcount == 0:
        abort(404)
    return jsonify({'annotations': [dict(row) for row in result]}), 200


@app.route('/memento/annotations/bycategory_id/<int:category_id>', methods=['GET'])
@token_required
def get_annotation_bycategory_id(category_id):
    conn = get_conn()
    sql = sqla.select([model.annotations.c.annotation_id, model.annotations.c.name, model.annotations.c.status, model.annotations.c.shared, model.annotations.c.image_id,
                       model.annotations.c.project_id, model.annotations.c.category_id, model.annotations.c.owner_id]).where(
        model.annotations.c.category_id == category_id).order_by(model.annotations.c.name.asc())
    result = conn.execute(sql)
    if result.rowcount == 0:
        abort(404)
    return jsonify({'annotations': [dict(row) for row in result]}), 200


@app.route('/memento/annotations/byimage_id/<int:image_id>', methods=['GET'])
@token_required
def get_annotation_byimage_id(image_id):
    conn = get_conn()
    sql = sqla.select([model.annotations.c.annotation_id, model.annotations.c.name, model.annotations.c.status, model.annotations.c.shared, model.annotations.c.image_id,
                       model.annotations.c.project_id, model.annotations.c.category_id, model.annotations.c.owner_id]).where(
        model.annotations.c.image_id == image_id).order_by(model.annotations.c.name.asc())
    result = conn.execute(sql)
    if result.rowcount == 0:
        abort(404)
    return jsonify({'annotations': [dict(row) for row in result]}), 200


@app.route('/memento/annotations/next/<int:project_id>/<int:category_id>', methods=['GET'])
@token_required
def get_next_annotation(project_id, category_id):
    conn = get_conn()

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
    conn = get_conn()
    sql = sqla.select([model.annotations_labels.c.annotation_id, model.annotations_labels.c.label_id])
    result = conn.execute(sql)
    return jsonify({'annotations_labels': [dict(row) for row in result]}), 200


@app.route('/memento/annotations_labels/<int:annotation_id>/<int:label_id>', methods=['GET'])
@token_required
def get_annotation_label(annotation_id, label_id):
    conn = get_conn()
    sql = sqla.select([model.annotations_labels.c.annotation_id, model.annotations_labels.c.label_id]).where(
        model.annotations_labels.c.annotation_id == annotation_id).where(
        model.annotations_labels.c.label_id == label_id)
    result = conn.execute(sql)
    if result.rowcount == 0:
        abort(404)
    return jsonify({'annotation_label': dict(result.first())}), 200


@app.route('/memento/annotations_labels', methods=['POST'])
@token_required
def create_annotation_label():
    if not request.json or not 'annotation_id' in request.json or not 'label_id' in request.json:
        abort(400)
    new_annotation_label = {
        'annotation_id': request.json['annotation_id'],
        'label_id': request.json['label_id'],
    }
    conn = get_conn()
    sql = model.annotations_labels.insert().values(annotation_id=new_annotation_label['annotation_id'], label_id=new_annotation_label['label_id'])
    result = conn.execute(sql)
    return jsonify({'annotation_label': new_annotation_label}), 201


@app.route('/memento/annotations_labels/<int:annotation_id>/<int:label_id>', methods=['DELETE'])
@token_required
def delete_annotation_label(annotation_id, label_id):
    conn = get_conn()
    sql = model.annotations_labels.delete().where(model.annotations_labels.c.annotation_id == annotation_id).where(
        model.annotations_labels.c.label_id == label_id)
    conn.execute(sql)
    return "", 204


@app.route('/memento/annotations_labels/byfilter/<int:annotation_id>/<int:label_id>', methods=['GET'])
@token_required
def get_annotations_labels_byfilter(annotation_id, label_id):
    conn = get_conn()
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
    conn = get_conn()
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
    conn = get_conn()
    sql = sqla.select([model.layers.c.layer_id, model.layers.c.name, model.layers.c.data, model.layers.c.image_id, model.layers.c.settings, model.layers.c.sequence, model.layers.c.parent_id, model.layers.c.annotation_id, model.layers.c.owner_id]).order_by(model.layers.c.sequence.asc())
    result = conn.execute(sql)
    return jsonify({'layers': [dict(row) for row in result]}), 200


@app.route('/memento/layers/<int:layer_id>', methods=['GET'])
@token_required
def get_layer(layer_id):
    conn = get_conn()
    sql = sqla.select([model.layers.c.layer_id, model.layers.c.name, model.layers.c.data, model.layers.c.image_id, model.layers.c.settings, model.layers.c.sequence, model.layers.c.parent_id, model.layers.c.annotation_id, model.layers.c.owner_id]).where(
        model.layers.c.layer_id == layer_id)
    result = conn.execute(sql)
    if result.rowcount == 0:
        abort(404)
    return jsonify({'layer': dict(result.first())}), 200


@app.route('/memento/layers', methods=['POST'])
@token_required
def create_layer():
    if not request.json or not 'name' in request.json or not 'data' in request.json or not 'image_id' in request.json or not 'settings' in request.json or not 'sequence' in request.json or not 'parent_id' in request.json or not 'annotation_id' in request.json or not 'project_id' in request.json or not 'owner_id' in request.json:
        abort(400)
    new_layer = {
        'name': request.json['name'],
        'data': request.json['data'],
        'image_id': request.json['image_id'],
        'settings': request.json['settings'],
        'sequence': request.json['sequence'],
        'parent_id': request.json['parent_id'],
        'annotation_id': request.json['annotation_id'],
        'project_id': request.json['project_id'],
        'owner_id': request.json['owner_id'],
    }
    conn = get_conn()
    sql = model.layers.insert().values(name=new_layer['name'], data=new_layer['data'], image_id=new_layer['image_id'], settings=new_layer['settings'], sequence=new_layer['sequence'], parent_id=new_layer['parent_id'], annotation_id=new_layer['annotation_id'], project_id=new_layer['project_id'], owner_id=new_layer['owner_id'])
    result = conn.execute(sql)
    new_layer['layer_id'] = result.inserted_primary_key[0]
    return jsonify({'layer': new_layer}), 201


@app.route('/memento/layers/<int:layer_id>', methods=['PUT'])
@token_required
def update_layer(layer_id):
    if not request.json or not 'name' in request.json or not 'data' in request.json or not 'image_id' in request.json or not 'settings' in request.json or not 'sequence' in request.json or not 'parent_id' in request.json or not 'annotation_id' in request.json or not 'project_id' in request.json or not 'owner_id' in request.json:
        abort(400)
    updated_layer = {
        'layer_id': layer_id,
        'name': request.json['name'],
        'data': request.json['data'],
        'image_id': request.json['image_id'],
        'settings': request.json['settings'],
        'sequence': request.json['sequence'],
        'parent_id': request.json['parent_id'],
        'annotation_id': request.json['annotation_id'],
        'project_id': request.json['project_id'],
        'owner_id': request.json['owner_id'],
    }
    conn = get_conn()
    sql = model.layers.update().values(name=updated_layer['name'], data=updated_layer['data'], image_id=updated_layer['image_id'], settings=updated_layer['settings'], sequence=updated_layer['sequence'], parent_id=updated_layer['parent_id'], annotation_id=updated_layer['annotation_id'], project_id=updated_layer['project_id'], owner_id=updated_layer['owner_id']). \
        where(model.layers.c.layer_id == layer_id)
    conn.execute(sql)
    return jsonify({'layer': updated_layer}), 201


@app.route('/memento/layers/<int:layer_id>', methods=['DELETE'])
@token_required
def delete_layer(layer_id):
    conn = get_conn()
    sql = model.layers.delete().where(model.layers.c.layer_id == layer_id)
    conn.execute(sql)
    return "", 204


@app.route('/memento/layers/byannotation_id/<int:annotation_id>', methods=['GET'])
@token_required
def get_layers_byannotation_id(annotation_id):
    conn = get_conn()
    sql = sqla.select([model.layers.c.layer_id, model.layers.c.name, model.layers.c.data, model.layers.c.image_id, model.layers.c.settings, model.layers.c.sequence, model.layers.c.parent_id, model.layers.c.annotation_id, model.layers.c.owner_id]).where(
        model.layers.c.annotation_id == annotation_id).order_by(model.layers.c.sequence.asc())
    result = conn.execute(sql)
    if result.rowcount == 0:
        abort(404)
    return jsonify({'layers': [dict(row) for row in result]}), 200


@app.route('/memento/layers/byimage_id/<int:image_id>', methods=['GET'])
@token_required
def get_layers_byimage_id(image_id):
    conn = get_conn()
    sql = sqla.select([model.layers.c.layer_id, model.layers.c.name, model.layers.c.data, model.layers.c.image_id, model.layers.c.settings, model.layers.c.sequence, model.layers.c.parent_id, model.layers.c.annotation_id, model.layers.c.owner_id]).where(
        model.layers.c.image_id == image_id).order_by(model.layers.c.sequence.asc())
    result = conn.execute(sql)
    if result.rowcount == 0:
        abort(404)
    return jsonify({'layers': [dict(row) for row in result]}), 200


@app.route('/memento/layers/byproject_id/<int:project_id>', methods=['GET'])
@token_required
def get_layers_byproject_id(project_id):
    conn = get_conn()
    sql = sqla.select([model.layers.c.layer_id, model.layers.c.name, model.layers.c.data, model.layers.c.image_id, model.layers.c.settings, model.layers.c.sequence, model.layers.c.parent_id, model.layers.c.annotation_id, model.layers.c.project_id, model.layers.c.owner_id]).where(
        model.layers.c.project_id == project_id).order_by(model.layers.c.sequence.asc())
    result = conn.execute(sql)
    if result.rowcount == 0:
        abort(404)
    return jsonify({'layers': [dict(row) for row in result]}), 200


@app.route('/memento/layers/byfilter/<int:annotation_id>/<int:sequence>', methods=['GET'])
@token_required
def get_layers_byfilter(annotation_id, sequence):
    conn = get_conn()
    sql = sqla.select([model.layers.c.layer_id, model.layers.c.name, model.layers.c.data, model.layers.c.image_id, model.layers.c.settings, model.layers.c.sequence, model.layers.c.parent_id, model.layers.c.annotation_id, model.layers.c.owner_id])
    if (annotation_id > 0):
        sql = sql.where(model.layers.c.annotation_id == annotation_id).order_by(model.layers.c.sequence.asc())
    if (sequence > 0):
        sql = sql.where(model.layers.c.sequence == sequence)
    result = conn.execute(sql)
    return jsonify({'layers': [dict(row) for row in result]}), 200


@app.route('/memento/comments', methods=['GET'])
@token_required
def get_comments():
    conn = get_conn()
    sql = sqla.select([model.comments.c.comment_id, model.comments.c.content, model.comments.c.sequence, model.comments.c.layer_id, model.comments.c.owner_id]).order_by(model.comments.c.sequence.asc())
    result = conn.execute(sql)
    return jsonify({'comments': [dict(row) for row in result]}), 200


@app.route('/memento/comments/<int:comment_id>', methods=['GET'])
@token_required
def get_comment(comment_id):
    conn = get_conn()
    sql = sqla.select([model.comments.c.comment_id, model.comments.c.content, model.comments.c.sequence, model.comments.c.layer_id, model.comments.c.owner_id]).where(
        model.comments.c.comment_id == comment_id)
    result = conn.execute(sql)
    if result.rowcount == 0:
        abort(404)
    return jsonify({'comment': dict(result.first())}), 200


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
    conn = get_conn()
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
    conn = get_conn()
    sql = model.comments.update().values(content=updated_comment['content'], sequence=updated_comment['sequence'], layer_id=updated_comment['layer_id'], owner_id=updated_comment['owner_id']). \
        where(model.comments.c.comment_id == comment_id)
    conn.execute(sql)
    return jsonify({'comment': updated_comment}), 201


@app.route('/memento/comments/<int:comment_id>', methods=['DELETE'])
@token_required
def delete_comment(comment_id):
    conn = get_conn()
    sql = model.comments.delete().where(model.comments.c.comment_id == comment_id)
    conn.execute(sql)
    return "", 204


@app.route('/memento/comments/bylayer_id/<int:layer_id>', methods=['GET'])
@token_required
def get_comment_bylayer_id(layer_id):
    conn = get_conn()
    sql = sqla.select([model.comments.c.comment_id, model.comments.c.content, model.comments.c.sequence, model.comments.c.layer_id, model.comments.c.owner_id]).where(
        model.comments.c.layer_id == layer_id).order_by(model.comments.c.sequence.asc())
    result = conn.execute(sql)
    if result.rowcount == 0:
        abort(404)
    return jsonify({'comments': [dict(row) for row in result]}), 200


@app.route('/memento/comments/byproject_id/<int:project_id>', methods=['GET'])
@token_required
def get_comments_byproject_id(project_id):
    conn = get_conn()
    sql = sqla.select([model.comments.c.comment_id, model.comments.c.content, model.comments.c.sequence, model.comments.c.layer_id, model.comments.c.project_id, model.comments.c.owner_id]).where(
        model.comments.c.project_id == project_id).order_by(model.comments.c.sequence.asc())
    result = conn.execute(sql)
    if result.rowcount == 0:
        abort(404)
    return jsonify({'comments': [dict(row) for row in result]}), 200


@app.route('/memento/utilities/change_ownership/<int:old_owner_id>/<int:new_owner_id>', methods=['PUT'])
@token_required
def change_ownership(old_owner_id, new_owner_id):
    conn = get_conn()
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
    sql = model.layers.update().values(owner_id=new_owner_id).where(model.layers.c.owner_id == old_owner_id)
    conn.execute(sql)
    sql = model.comments.update().values(owner_id=new_owner_id).where(model.comments.c.owner_id == old_owner_id)
    conn.execute(sql)
    return "", 200


@app.route('/memento/utilities/project_summary/<int:project_id>', methods=['GET'])
@token_required
def project_summary(project_id):
    conn = get_conn()
    new_project_summary = {}

    # Count distinct participants across all permission types for this project.
    # propar: directly references the project by project_id
    propar_q = sqla.select([model.permissions.c.user_id]).where(
        model.permissions.c.type == 'propar').where(
        model.permissions.c.type_id == project_id)
    # catpar: references a category that belongs to this project
    catpar_q = sqla.select([model.permissions.c.user_id]).where(
        model.permissions.c.type == 'catpar').where(
        model.permissions.c.type_id.in_(
            sqla.select([model.categories.c.category_id]).where(
                model.categories.c.project_id == project_id)))
    # annpar: references an annotation that belongs to this project
    annpar_q = sqla.select([model.permissions.c.user_id]).where(
        model.permissions.c.type == 'annpar').where(
        model.permissions.c.type_id.in_(
            sqla.select([model.annotations.c.annotation_id]).where(
                model.annotations.c.project_id == project_id)))
    participants_subq = sqla.union(propar_q, catpar_q, annpar_q).alias('participants')
    result = conn.execute(sqla.select([sqla.func.count()]).select_from(participants_subq))
    new_project_summary['total_participants'] = result.scalar()

    # Count annotations in a single pass using conditional aggregation.
    ann = model.annotations
    sql = sqla.select([
        sqla.func.count().label('total'),
        sqla.func.sum(sqla.case([(ann.c.status == 'S', 1)], else_=0)).label('submitted'),
        sqla.func.sum(sqla.case([(ann.c.shared != '', 1)], else_=0)).label('shared'),
    ]).where(ann.c.project_id == project_id)
    result = conn.execute(sql)
    row = result.first()
    new_project_summary['total_annotations'] = row['total']
    new_project_summary['total_annotations_submitted'] = row['submitted']
    new_project_summary['total_annotations_shared'] = row['shared']

    return jsonify(new_project_summary), 200


@app.route('/memento/utilities/project_data/<int:project_id>', methods=['GET'])
@token_required
def project_data(project_id):
    conn = get_conn()

    result = conn.execute('select pro.name as project, cat.name as category, cla.name as classification, ann.name as annotation, img.name as image, ann.status as status, lab.name as label, img.uri as image_uri from projects pro, images img, categories cat left outer join categories_classifications catcla on cat.category_id=catcla.category_id left outer join classifications cla on catcla.classification_id=cla.classification_id, annotations ann left outer join annotations_labels annlab on ann.annotation_id=annlab.annotation_id left outer join labels lab on annlab.label_id=lab.label_id where ann.project_id=pro.project_id and ann.category_id=cat.category_id and ann.image_id=img.image_id and ann.project_id=%s', project_id)
    return jsonify({'project_data': [dict(row) for row in result]}), 200


@app.route('/memento/utilities/project_comments/<int:project_id>', methods=['GET'])
@token_required
def project_comments(project_id):
    conn = get_conn()

    result = conn.execute('select pro.name as project, cat.name as category, ann.name as annotation, lay.name as layer, com.content as content from projects pro, categories cat, annotations ann, layers lay, comments com where com.project_id=%s and lay.layer_id=com.layer_id and ann.annotation_id=lay.annotation_id and ann.category_id=cat.category_id and pro.project_id=com.project_id', project_id)
    return jsonify({'project_comments': [dict(row) for row in result]}), 200


@app.route('/memento/utilities/project_rois/<int:project_id>', methods=['GET'])
@token_required
def project_rois(project_id):
    conn = get_conn()

    result = conn.execute('select pro.name as project, cat.name as category, ann.name as annotation, lay.name as layer, lay.data as data from projects pro, categories cat, annotations ann, layers lay where lay.project_id=%s and ann.annotation_id=lay.annotation_id and ann.category_id=cat.category_id and pro.project_id=lay.project_id', project_id)
    return jsonify({'project_rois': [dict(row) for row in result]}), 200


if __name__ == '__main__':
   app.run()
