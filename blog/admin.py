from django.contrib import admin
from blog.models import post,contact
# Register your models here.
@admin.register(post)
class blogadmin(admin.ModelAdmin):
    list_display=['id','user','title','disc']

@admin.register(contact)
class contactadmin(admin.ModelAdmin):
    list_display=['id','name','email','subject','message']