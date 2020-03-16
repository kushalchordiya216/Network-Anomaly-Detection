from django.shortcuts import render
from django.views import View
from .apps import IntrusionConfig as IC
from .runArgus import run_cmd
from django.conf import settings
from .parsing import ip_port_split_1, ip_port_split_2
import re
import pandas as pd
import numpy as np
from .ct_srv_src import *

# Create your views here.
class InferView(View):
    template_name = 'index.html'

    def get(self,request):
        return render(request,self.template_name,{})

    def post(self,request):
        pcap_file = request.FILES['pcap_file']
        ###scripts
        f = open(settings.MEDIA_ROOT+str('pcap_file.pcap'),'wb')
        for chunk in pcap_file.chunks():
            f.write(chunk)
        run_cmd(settings.MEDIA_ROOT+str('pcap_file.pcap'))
        with open(str(settings.MEDIA_ROOT)+str('pcap_file_txt.txt'),'r+') as f:
            line = f.readline().strip()
            headings = re.split('\s+', line)
            headings.remove('Dir')
            headings.remove('Flgs')
            #print(len(headings))
            #print(headings)
            matrix = []
            line = f.readline().strip()
            while line:
                data = re.split('\s+', line)
                data.pop(2)
                data.pop(4)
                if ip_port_split_1(data) and ip_port_split_2(data):
                    matrix.append(data)
                    print(data)
                    print(len(data))
                line = f.readline().strip()
            #print(matrix)
            df = pd.DataFrame(matrix)
            df.columns = headings
            get_ct_srv_src(df)
            get_ct_srv_dst(df)
            #df_copy = df.copy(deep=True)
            #anomaly_df = preproc_anomaly(df_copy) 
            timestamps = df['StartTime'] 
            ip = df['SrcAddr']
            df.drop(['SrcAddr', 'DstAddr', 'TotPkts', 'TotBytes', 'StartTime'], axis=1, inplace=True)
            df = df[['Proto', 'SrcPkts', 'DstPkts', 'TcpRtt', 'State', 'Dur', 'SrcBytes', 'DstBytes', 'ct_srv_src', 'ct_srv_dst']]
            df.columns = ['proto', 'Spkts', 'Dpkts', 'tcprtt', 'state', 'dur', 'sbytes', 'dbytes', 'ct_srv_src', 'ct_srv_dst']
            df = pd.get_dummies(df,columns=['proto', 'state'])
            total_features = ['Spkts','Dpkts','tcprtt','dur','sbytes','dbytes','ct_srv_src','ct_srv_dst','proto_3pc','proto_a/n','proto_aes-sp3-d','proto_any','proto_argus','proto_aris','proto_arp','proto_ax.25','proto_bbn-rcc','proto_bna','proto_br-sat-mon','proto_cbt','proto_cftp','proto_chaos','proto_compaq-peer','proto_cphb','proto_cpnx','proto_crtp','proto_crudp','proto_dcn','proto_ddp','proto_ddx','proto_dgp','proto_egp','proto_eigrp','proto_emcon','proto_encap','proto_esp','proto_etherip','proto_fc','proto_fire','proto_ggp','proto_gmtp','proto_gre','proto_hmp','proto_i-nlsp','proto_iatp','proto_ib','proto_icmp','proto_idpr','proto_idpr-cmtp','proto_idrp','proto_ifmp','proto_igmp','proto_igp','proto_il','proto_ip','proto_ipcomp','proto_ipcv','proto_ipip','proto_iplt','proto_ipnip','proto_ippc','proto_ipv6','proto_ipv6-frag','proto_ipv6-no','proto_ipv6-opts','proto_ipv6-route','proto_ipx-n-ip','proto_irtp','proto_isis','proto_iso-ip','proto_iso-tp4','proto_kryptolan','proto_l2tp','proto_larp','proto_leaf-1','proto_leaf-2','proto_merit-inp','proto_mfe-nsp','proto_mhrp','proto_micp','proto_mobile','proto_mtp','proto_mux','proto_narp','proto_netblt','proto_nsfnet-igp','proto_nvp','proto_ospf','proto_pgm','proto_pim','proto_pipe','proto_pnni','proto_pri-enc','proto_prm','proto_ptp','proto_pup','proto_pvp','proto_qnx','proto_rdp','proto_rsvp','proto_rtp','proto_rvd','proto_sat-expak','proto_sat-mon','proto_sccopmce','proto_scps','proto_sctp','proto_sdrp','proto_secure-vmtp','proto_sep','proto_skip','proto_sm','proto_smp','proto_snp','proto_sprite-rpc','proto_sps','proto_srp','proto_st2','proto_stp','proto_sun-nd','proto_swipe','proto_tcf','proto_tcp','proto_tlsp','proto_tp++','proto_trunk-1','proto_trunk-2','proto_ttp','proto_udp','proto_udt','proto_unas','proto_uti','proto_vines','proto_visa','proto_vmtp','proto_vrrp','proto_wb-expak','proto_wb-mon','proto_wsn','proto_xnet','proto_xns-idp','proto_xtp','proto_zero','state_ACC','state_CLO','state_CON','state_ECO','state_ECR','state_FIN','state_INT','state_MAS','state_PAR','state_REQ','state_RST','state_TST','state_TXD','state_URH','state_URN','state_no']
            for feature in total_features:
                if feature not in df.columns:
                    df[feature] = df.apply(lambda x:'0',axis=1)
            for feature in df.columns:
                if feature not in total_features:
                    df.drop([feature],axis=1,inplace=True)
            pred = IC.bin_model.predict(df)
            '''a_ls = pd.DataFrame()
            for i,p in enumerate(pred):
                if p == 1:
                    a_ls[i] = anomaly_df.iloc[i]
                print(a_ls)
            
            attack_cat = IC.att_model.predict(a_ls)
            results = np.argmax(attack_cat)
            attacks = ['Generic/Brute Force','DoS','Port Scanning','Privilege Escalation']'''
            out_df = pd.DataFrame({'SrcIP':ip,'Timestamp':timestamps,'Anomaly 0/1':pred})
            out_df.to_csv(str(settings.MEDIA_ROOT)+'out.csv',index=False)
        return render(request,self.template_name,{'out_flag':1})#{'ano':ano,'att_class':att_class}

'''def preproc_anomaly(df):
    df = df.drop(columns=['srcip','dstip'])
    df['attack_cat'].fillna('Normal',inplace=True)
    df = df[df['attack_cat']!='Normal']
    df['attack_cat']=df['attack_cat'].apply(lambda x:x.strip())
    df['attack_cat'].replace(to_replace='Exploits',value='DoS',inplace=True)
    df['attack_cat'].replace(to_replace='Fuzzers',value='DoS',inplace=True)
    df['attack_cat'].replace(to_replace='Reconnaissance',value='Port Scan',inplace=True)
    df['attack_cat'].replace(to_replace='Analysis',value='Port Scan',inplace=True)
    df['attack_cat'].replace(to_replace='Backdoors',value='Privilege Escalation',inplace=True)
    df['attack_cat'].replace(to_replace='Backdoor',value='Privilege Escalation',inplace=True)
    df['attack_cat'].replace(to_replace='Shellcode',value='Privilege Escalation',inplace=True)
    df['attack_cat'].replace(to_replace='Worms',value='Privilege Escalation',inplace=True)
    X = df.drop(columns='attack_cat')
    X = df[['proto','Spkts','Dpkts','tcprtt','state','dur','sbytes','dbytes','ct_srv_src','ct_srv_dst']] #'sport','dsport','ct_state_ttl'
    X = pd.get_dummies(X,columns=['proto','state'])
    return X'''