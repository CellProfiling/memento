import sqlalchemy as sqla
import os

database_desc = 'mysql+mysqlconnector://' + os.environ.get("MYSQL_MEMENTO_USER") + ':' + os.environ.get("MYSQL_MEMENTO_PASSWORD") + '@' + os.environ.get("MYSQL_HOSTNAME") + ':' + os.environ.get("MYSQL_PORT") + '/' + os.environ.get("MYSQL_MEMENTO_DATABASE")
engine = sqla.create_engine(database_desc, pool_recycle=3600, pool_size=20, max_overflow=50)
metadata = sqla.MetaData()
users = sqla.Table('users', metadata,
    sqla.Column('user_id', sqla.Integer, primary_key=True),
    sqla.Column('username', sqla.String(50), nullable=False, unique=True),
    sqla.Column('name', sqla.String(255), nullable=False),
    sqla.Column('password', sqla.String(255), nullable=False),
    sqla.Column('email', sqla.String(255), nullable=False),
    sqla.Column('settings', sqla.Text, nullable=False),
)
permissions = sqla.Table('permissions', metadata,
    sqla.Column('user_id', sqla.Integer, nullable=False),
    sqla.Column('type', sqla.String(8), nullable=False),
    sqla.Column('type_id', sqla.Integer, nullable=False),
)
sqla.Index('idx_permissions_user_id', permissions.c.user_id)
sqla.Index('idx_permissions_type_type_id', permissions.c.type, permissions.c.type_id)
projects = sqla.Table('projects', metadata,
    sqla.Column('project_id', sqla.Integer, primary_key=True),
    sqla.Column('name', sqla.String(255), nullable=False, unique=True),
    sqla.Column('owner_id', sqla.Integer, nullable=False),
    sqla.Column('settings', sqla.Text, nullable=False),
)
categories = sqla.Table('categories', metadata,
    sqla.Column('category_id', sqla.Integer, primary_key=True),
    sqla.Column('name', sqla.String(255), nullable=False),
    sqla.Column('project_id', sqla.Integer, nullable=False, index=True),
    sqla.Column('owner_id', sqla.Integer, nullable=False),
    sqla.Column('settings', sqla.Text, nullable=False),
)
classifications = sqla.Table('classifications', metadata,
    sqla.Column('classification_id', sqla.Integer, primary_key=True),
    sqla.Column('name', sqla.String(255), nullable=False),
    sqla.Column('type', sqla.String(8), nullable=False),
    sqla.Column('data', sqla.Text, nullable=False),
    sqla.Column('project_id', sqla.Integer, nullable=False, index=True),
    sqla.Column('owner_id', sqla.Integer, nullable=False),
    sqla.Column('settings', sqla.Text, nullable=False),
)
categories_classifications = sqla.Table('categories_classifications', metadata,
    sqla.Column('category_id', sqla.Integer, nullable=False),
    sqla.Column('classification_id', sqla.Integer, nullable=False),
)
sqla.Index('idx_catcla_category_id', categories_classifications.c.category_id)
sqla.Index('idx_catcla_classification_id', categories_classifications.c.classification_id)
labels = sqla.Table('labels', metadata,
    sqla.Column('label_id', sqla.Integer, primary_key=True),
    sqla.Column('name', sqla.String(255), nullable=False),
    sqla.Column('project_id', sqla.Integer, nullable=False, index=True),
    sqla.Column('owner_id', sqla.Integer, nullable=False),
)
images = sqla.Table('images', metadata,
    sqla.Column('image_id', sqla.Integer, primary_key=True),
    sqla.Column('name', sqla.String(255), nullable=False),
    sqla.Column('uri', sqla.String(1000), nullable=False),
    sqla.Column('type', sqla.String(1), nullable=False),
    sqla.Column('resolution', sqla.String(255), nullable=False),
    sqla.Column('project_id', sqla.Integer, nullable=False, index=True),
    sqla.Column('owner_id', sqla.Integer, nullable=False),
)
annotations = sqla.Table('annotations', metadata,
    sqla.Column('annotation_id', sqla.Integer, primary_key=True),
    sqla.Column('name', sqla.String(255), nullable=False),
    sqla.Column('status', sqla.String(1), nullable=False, index=True),
    sqla.Column('shared', sqla.String(255), nullable=False),
    sqla.Column('image_id', sqla.Integer, nullable=False, index=True),
    sqla.Column('project_id', sqla.Integer, nullable=False, index=True),
    sqla.Column('category_id', sqla.Integer, nullable=False, index=True),
    sqla.Column('owner_id', sqla.Integer, nullable=False),
)
annotations_labels = sqla.Table('annotations_labels', metadata,
    sqla.Column('annotation_id', sqla.Integer, nullable=False),
    sqla.Column('label_id', sqla.Integer, nullable=False),
)
sqla.Index('idx_annlab_annotation_id', annotations_labels.c.annotation_id)
sqla.Index('idx_annlab_label_id', annotations_labels.c.label_id)
layers = sqla.Table('layers', metadata,
    sqla.Column('layer_id', sqla.Integer, primary_key=True),
    sqla.Column('name', sqla.String(255), nullable=False),
    sqla.Column('data', sqla.Text, nullable=False),
    sqla.Column('image_id', sqla.Integer, nullable=False, index=True),
    sqla.Column('settings', sqla.Text, nullable=False),
    sqla.Column('sequence', sqla.Integer, nullable=False),
    sqla.Column('parent_id', sqla.Integer, nullable=False),
    sqla.Column('annotation_id', sqla.Integer, nullable=False, index=True),
    sqla.Column('project_id', sqla.Integer, nullable=False, index=True),
    sqla.Column('owner_id', sqla.Integer, nullable=False),
)
comments = sqla.Table('comments', metadata,
    sqla.Column('comment_id', sqla.Integer, primary_key=True),
    sqla.Column('content', sqla.Text, nullable=False),
    sqla.Column('sequence', sqla.Integer, nullable=False),
    sqla.Column('layer_id', sqla.Integer, nullable=False, index=True),
    sqla.Column('project_id', sqla.Integer, nullable=False, index=True),
    sqla.Column('owner_id', sqla.Integer, nullable=False),
)