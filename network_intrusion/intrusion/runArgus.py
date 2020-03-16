import os
from django.conf import settings

def run_cmd(pcap_file_path):
    os.system('argus -r'+ str(pcap_file_path)+' -w - | ra -s +1dur +tcprtt +spkts +dpkts +sbytes +dbytes > '+str(settings.MEDIA_ROOT)+str('pcap_file_txt.txt'))