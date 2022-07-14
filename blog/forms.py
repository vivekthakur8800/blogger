from django import forms
from blog.models import post,contact
from django.contrib.auth.forms import UserCreationForm
from django.contrib.auth.models import User
class postform(forms.ModelForm):
    class Meta:
        model=post
        fields=['user','title','disc']
        

class signupform(UserCreationForm):
    class Meta:
        model=User
        fields=['username','first_name','last_name','email']
        widgets={
            'username':forms.TextInput(attrs={'placeholder':'Username'}),
            'first_name':forms.TextInput(attrs={'placeholder':'First Name'}),
            'last_name':forms.TextInput(attrs={'placeholder':'Last Name'}),
        }

class contactform(forms.ModelForm):
    # name=forms.CharField(widget=forms.te)
    class Meta:
        model=contact
        fields=['name','email','subject','message']
        widgets={
            'name':forms.TextInput(attrs={'class':'form-control'}),
            'email':forms.EmailInput(attrs={'class':'form-control'}),
            'subject':forms.TextInput(attrs={'class':'form-control'}),
            'message':forms.Textarea(attrs={'class':'form-control'}),
        }