from django.contrib import admin
from django.urls import path
from intrusion.views import *

urlpatterns = [
    path('', InferView.as_view(),name='infer_view')

]