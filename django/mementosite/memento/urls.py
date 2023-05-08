from django.urls import path

from . import views


urlpatterns = [
    path('', views.home, name='home'),
    path('login', views.login_user, name='login_user'),
    path('logout', views.logout_user, name='logout_user'),
    path('manage_users', views.manage_users, name='manage_users'),
    path('new_user', views.new_user, name='new_user'),
    path('edit_user', views.edit_user, name='edit_user'),
    path('delete_user', views.delete_user, name='delete_user'),
    path('change_password', views.change_password, name='change_password'),
    path('update_permission', views.update_permission, name='update_permission'),
    path('manage_projects', views.manage_projects, name='manage_projects'),
    path('ft_share_image', views.ft_share_image, name='ft_share_image'),
    path('new_project', views.new_project, name='new_project'),
    path('edit_project', views.edit_project, name='edit_project'),
    path('delete_project', views.delete_project, name='delete_project'),
    path('new_participant', views.new_participant, name='new_participant'),
    path('edit_participant', views.edit_participant, name='edit_participant'),
    path('delete_participant', views.delete_participant, name='delete_participant'),
    path('new_viewer', views.new_viewer, name='new_viewer'),
    path('edit_viewer', views.edit_viewer, name='edit_viewer'),
    path('delete_viewer', views.delete_viewer, name='delete_viewer'),
    path('new_label', views.new_label, name='new_label'),
    path('edit_label', views.edit_label, name='edit_label'),
    path('delete_label', views.delete_label, name='delete_label'),
    path('new_category', views.new_category, name='new_category'),
    path('edit_category', views.edit_category, name='edit_category'),
    path('delete_category', views.delete_category, name='delete_category'),
    path('new_classification', views.new_classification, name='new_classification'),
    path('edit_classification', views.edit_classification, name='edit_classification'),
    path('delete_classification', views.delete_classification, name='delete_classification'),
    path('new_image', views.new_image, name='new_image'),
    path('edit_image', views.edit_image, name='edit_image'),
    path('delete_image', views.delete_image, name='delete_image'),
    path('new_annotation', views.new_annotation, name='new_annotation'),
    path('edit_annotation', views.edit_annotation, name='edit_annotation'),
    path('delete_annotation', views.delete_annotation, name='delete_annotation'),
    path('update_share_annotation', views.update_share_annotation, name='update_share_annotation'),
    path('delete_annotation_labels', views.delete_annotation_labels, name='delete_annotation_labels'),
    path('new_layer', views.new_layer, name='new_layer'),
    path('edit_layer', views.edit_layer, name='edit_layer'),
    path('delete_layer', views.delete_layer, name='delete_layer'),
    path('viewer', views.viewer, name='viewer'),
    path('viewer_limited', views.viewer_limited, name='viewer_limited'),
    path('image_grid', views.image_grid, name='image_grid'),
    path('annotations_limited', views.annotations_limited, name='annotations_limited'),
    path('image_editor', views.image_editor, name='image_editor'),
    path('layer_editor', views.layer_editor, name='layer_editor'),
    path('annotation_editor', views.annotation_editor, name='annotation_editor'),
    path('classification_editor', views.classification_editor, name='classification_editor'),
    path('next_annotation', views.next_annotation, name='next_annotation'),
    path('comment_editor', views.comment_editor, name='comment_editor'),
    path('submit_share_annotation', views.submit_share_annotation, name='submit_share_annotation'),
    path('new_layer_viewer', views.new_layer_viewer, name='new_layer_viewer'),
    path('delete_layer_viewer', views.delete_layer_viewer, name='delete_layer_viewer'),
    path('save_layer_viewer', views.save_layer_viewer, name='save_layer_viewer'),
    path('submit_annotation_labels', views.submit_annotation_labels, name='submit_annotation_labels'),
    path('submit_classification', views.submit_classification, name='submit_classification'),
    path('submit_comment', views.submit_comment, name='submit_comment'),
    path('delete_comment_viewer', views.delete_comment_viewer, name='delete_comment_viewer'),
    path('media/<int:id>/<str:options>', views.serve_image, name='serve_image'),
    path('export_data', views.export_data, name='export_data'),
    path('export_comments', views.export_comments, name='export_comments'),
    path('export_rois', views.export_rois, name='export_rois')
]

