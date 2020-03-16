# %%
import csv
import pandas as pd 
import re 

# %%
def ip_port_split_1(l):
    src_pair = l[3].split(".")
    if len(src_pair)>=4:
        pair = ".".join(src_pair[:4])
        if 'mdns' in l[3]:
            l.insert(4,'5353')
            l[3] = pair
            return True 
        elif 'netbi' in l[3]:
            l.insert(4,'139')
            l[3] = pair
            return True
        elif 'bootps' in l[3] or 'bootpc' in l[3]:
            l.insert(4,'67')
            l[3] = pair
            return True
        if l[2] not in ['udp','tcp', 'http', 'ftp', 'stp', 'imap', 'ssh']:
            l.insert(4,'0')
        else:
            try:     
                l.insert(4,src_pair[4])
            except Exception:
                l.insert(4,'0')
        l[3] = pair
        return True
    else: return False

def ip_port_split_2(l):
    dst_pair = l[5].split(".")
    if len(dst_pair)>=4:
        pair = ".".join(dst_pair[:4])
        if 'mdns' in l[5]:
            l.insert(6,'5353')
            l[5] = pair
            return True 
        elif 'netbi' in l[5]:
            l.insert(6,'139')
            l[5] = pair
            return True
        elif 'bootps' in l[5] or 'bootpc' in l[5]:
            l.insert(6,'67')
            l[5] = pair
            return True
        if l[2] not in ['udp','tcp', 'http', 'ftp', 'stp', 'imap', 'ssh']:
            l.insert(6,'0')
        else:
            try:     
                l.insert(6,dst_pair[4])
            except Exception:
                l.insert(4,'0')
        l[5] = pair
        return True
    else: return False
