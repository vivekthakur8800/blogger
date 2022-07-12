from rest_framework import serializers
from blog.models import post
class PostSerializers(serializers.ModelSerializer):
    class Meta:
        model=post
        fields=['id','user','title','disc']