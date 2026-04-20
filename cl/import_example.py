import memento_cl
import os
import sys


### Example command to call the script:   python3 import_example.py test_proj

#Change the following variables with your credentials
cr_username = 'username'
cr_password = 'password'

#Login, get your memento user_id to mark you as the owner of all your memento projects/operations
login_res = memento_cl.login(cr_username, cr_password)
if login_res == -1:
    print("Incorrect credentials")
    quit()

#Get your memento user_id to mark you as the owner of all your memento projects/operations
user_id = memento_cl.get_user_id(cr_username)

#Create a new memento project with name equal to the first argument. This must be the same name of the top directory containing the images' folder structure
project_name = sys.argv[1]

project_id = memento_cl.new_project(user_id, project_name, '')
if (project_id == -1):
    print("Could not create project " + project_name)
    quit()

print("Created project " + project_name + " with id " + str(project_id))
#NOTE: a memento project can only be created once. Write down the project_id if you plan to modify it later on.
# As you will notice in the following part of the script, we try to delete the whole project in case of error so you can fully re-run it

# Now we iterate over the top directory' folders
project_dir = os.listdir(project_name)
project_dir.sort()
for f_cat in project_dir:
    #For each existing folder we create a memento category.
    category_id = memento_cl.new_category(user_id, project_id, f_cat, '')
    if (category_id == -1):
        memento_cl.delete_project(user_id, project_id)
        print("Could not create category " + f_cat)
        quit()
    print("Created category " + f_cat + " with id " + str(category_id))

    #Now we iterate over the folder's images
    num_img = 1
    annotation_id = -1
    layer_sequence = 1
    category_dir = sorted(os.listdir(project_name + '/' + f_cat), reverse=True)
    for f_ann in category_dir:
        #We iterate over the annotations
        annotation_dir = sorted(os.listdir(project_name + '/' + f_cat + '/' + f_ann), reverse=True)
        for f_gl in annotation_dir:
            #We iterate over the layer groups
            group_layer_id = -1
            gl_dir = sorted(os.listdir(project_name + '/' + f_cat + '/' + f_ann + '/' + f_gl), reverse=True)
            for f_img in gl_dir:
                #For the first image in the folder we create the wrapping annotation
                if (num_img == 1):
                    #First, we upload the image, PNG rescaled
                    image_id = memento_cl.upload_image(user_id, project_id, project_name + '/' + f_cat + '/' + f_ann + '/' + f_gl + '/' + f_img, 2, f_cat + '_' + f_ann + '_' + f_gl + '_' + f_img, '', '')
                    if (image_id == -1):
                        memento_cl.delete_project(user_id, project_id)
                        print("Could not create image " + f_img)
                        quit()
                    print("Uploaded image " + f_cat + '_' + f_ann + '_' + f_gl + '_' + f_img + " with id " + str(image_id))
                    #Second, we create the wrapping annotation. As annotation name we use the annotation folder name.
                    annotation_name = f_ann
                    #For the first layer, we use the group layer name
                    layer_name = f_gl
                    annotation_id, group_layer_id = memento_cl.new_annotation(user_id, project_id, category_id, 0, annotation_name, layer_name, layer_sequence + 3, 0)
                    if (annotation_id == -1):
                        memento_cl.delete_project(user_id, project_id)
                        print("Could not create annotation " + annotation_name)
                        quit()
                    print("Created annotation with name " + annotation_name + " and id " + str(annotation_id))
                    #For the first sub-layer, we use the image filename
                    layer_name = f_img
                    layer_id = memento_cl.new_image_layer(user_id, project_id, category_id, annotation_id, image_id, layer_name, layer_sequence, group_layer_id)
                    if (layer_id == -1):
                        memento_cl.delete_project(user_id, project_id)
                        print("Could not create layer " + layer_name)
                        quit()
                    layer_sequence = layer_sequence + 1
                #For the other other images in the folder we create additional layers
                else:
                    #First, we upload the image
                    image_id = memento_cl.upload_image(user_id, project_id, project_name + '/' + f_cat + '/' + f_ann + '/' + f_gl + '/' + f_img, 2, f_cat + '_' + f_ann + '_' + f_gl + '_' + f_img, '', '')
                    print("Uploaded image " + f_cat + '_' + f_ann + '_' + f_gl + '_' + f_img + " with id " + str(image_id))
                    if (image_id == -1):
                        memento_cl.delete_project(user_id, project_id)
                        print("Could not create image " + f_img)
                        quit()
                    #Second, we create the additional layer. As layer name we use ('image' + num_img)
                    layer_name = f_img
                    layer_id = memento_cl.new_image_layer(user_id, project_id, category_id, annotation_id, image_id, layer_name, layer_sequence, group_layer_id)
                    if (layer_id == -1):
                        memento_cl.delete_project(user_id, project_id)
                        print("Could not create layer " + layer_name)
                        quit()
                    layer_sequence = layer_sequence + 1
                    print("Created layer with name " + layer_name + " and id " + str(layer_id))

                num_img = num_img + 1
