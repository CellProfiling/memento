from django import forms


class NewUserForm(forms.Form):
    username = forms.CharField(label='Username', max_length=50)
    name = forms.CharField(label='Name', max_length=255)
    email = forms.CharField(label='Email', max_length=255)
    password = forms.CharField(label='Password', max_length=100)
    password_r = forms.CharField(label='Repeat password', max_length=100)
    usettings = forms.CharField(label='Settings', max_length=1000, required=False)


class ChangePasswordForm(forms.Form):
    password = forms.CharField(label='Password', max_length=100)
    password_r = forms.CharField(label='Repeat password', max_length=100)
    usettings = forms.CharField(label='Settings', max_length=1000, required=False)


class NewFTShareImageForm(forms.Form):
    name = forms.CharField(label='Name', max_length=255)
    file = forms.ImageField()
    format = forms.CharField(label='Format', max_length=1)
    url = forms.CharField(label='URL', max_length=1000)


class NewProjectForm(forms.Form):
    name = forms.CharField(label='Name', max_length=255)
    psettings = forms.CharField(label='Settings', max_length=1000, required=False)


class NewParticipantForm(forms.Form):
    user_id = forms.IntegerField()


class NewViewerForm(forms.Form):
    user_id = forms.IntegerField()


class NewLabelForm(forms.Form):
    name = forms.CharField(label='Name', max_length=255)


class NewCategoryForm(forms.Form):
    name = forms.CharField(label='Name', max_length=255)
    csettings = forms.CharField(label='Settings', max_length=1000, required=False)


class NewClassificationForm(forms.Form):
    name = forms.CharField(label='Name', max_length=255)
    type = forms.CharField(label='Type', max_length=1)
    data = forms.CharField(label='Data', max_length=1000)
    clsettings = forms.CharField(label='Settings', max_length=1000, required=False)


class NewImageForm(forms.Form):
    name = forms.CharField(label='Name', max_length=255)
    file = forms.ImageField()
    format = forms.CharField(label='Format', max_length=1)
    url = forms.CharField(label='URL', max_length=1000)


class EditImageForm(forms.Form):
    name = forms.CharField(label='Name', max_length=255)


class NewAnnotationForm(forms.Form):
    name = forms.CharField(label='Name', max_length=255)
    image_id = forms.IntegerField()
    status = forms.CharField(label='Status', max_length=1)


class NewLayerForm(forms.Form):
    name = forms.CharField(label='Name', max_length=255)
    image_id = forms.IntegerField()
