from django.apps import AppConfig
from django.conf import settings
import os
import pickle

class IntrusionConfig(AppConfig):
    name = 'intrusion'
    bin_model_path = os.path.join(settings.MODELS,'randomforests_final.pkl')
    att_model_path = os.path.join(settings.MODELS,'att_classes.pkl')
    with open(bin_model_path,'rb') as f:
        bin_model = pickle.load(f)
    with open(att_model_path,'rb') as f:
        att_model = pickle.load(f)