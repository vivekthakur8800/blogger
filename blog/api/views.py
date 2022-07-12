from rest_framework import viewsets
from blog.api.serializers import PostSerializers
from blog.models import post
# from rest_framework.authentication import BasicAuthentication
from rest_framework_simplejwt.authentication import JWTAuthentication
from rest_framework.permissions import IsAuthenticatedOrReadOnly
class postview(viewsets.ModelViewSet):
    queryset=post.objects.all()
    serializer_class=PostSerializers
    # authentication_classes=[BasicAuthentication]
    authentication_classes=[JWTAuthentication]
    permission_classes=[IsAuthenticatedOrReadOnly]