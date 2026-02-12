from django.http import HttpResponse
from django.urls import path

def home(request):
    return HttpResponse('<html><body><h1>Django Test</h1><a href="/about">About</a></body></html>')

def about(request):
    return HttpResponse('<html><body><h1>About</h1><a href="/">Home</a></body></html>')

urlpatterns = [
    path('', home),
    path('about', about),
]
