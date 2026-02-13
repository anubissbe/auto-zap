from django.http import HttpResponse
from django.urls import path
urlpatterns = [path("", lambda r: HttpResponse("<h1>Hello from Django</h1>"))]
