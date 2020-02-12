# %%
import pandas as pd
import pickle
from sklearn.ensemble import RandomForestClassifier, GradientBoostingClassifier
from sklearn.model_selection import train_test_split, cross_validate
from sklearn.metrics import accuracy_score,precision_score, recall_score, f1_score, make_scorer
# %%
df = pd.read_csv('pcaps/UNSW_NB15_testing-set.csv')
# %%
y = df['label']
X = df[['proto', 'spkts', 'dpkts', 'tcprtt', 'state', 'dur', 'sbytes',
        'dbytes', 'ct_srv_src', 'ct_srv_dst']]  # 'sport','dsport'
X = pd.get_dummies(X, columns=['proto', 'state'])
# %%
total_features = ['spkts','dpkts','tcprtt','dur','sbytes','dbytes','ct_srv_src','ct_srv_dst','proto_3pc','proto_a/n','proto_aes-sp3-d','proto_any','proto_argus','proto_aris','proto_arp','proto_ax.25','proto_bbn-rcc','proto_bna','proto_br-sat-mon','proto_cbt','proto_cftp','proto_chaos','proto_compaq-peer','proto_cphb','proto_cpnx','proto_crtp','proto_crudp','proto_dcn','proto_ddp','proto_ddx','proto_dgp','proto_egp','proto_eigrp','proto_emcon','proto_encap','proto_esp','proto_etherip','proto_fc','proto_fire','proto_ggp','proto_gmtp','proto_gre','proto_hmp','proto_i-nlsp','proto_iatp','proto_ib','proto_icmp','proto_idpr','proto_idpr-cmtp','proto_idrp','proto_ifmp','proto_igmp','proto_igp','proto_il','proto_ip','proto_ipcomp','proto_ipcv','proto_ipip','proto_iplt','proto_ipnip','proto_ippc','proto_ipv6','proto_ipv6-frag','proto_ipv6-no','proto_ipv6-opts','proto_ipv6-route','proto_ipx-n-ip','proto_irtp','proto_isis','proto_iso-ip','proto_iso-tp4','proto_kryptolan','proto_l2tp','proto_larp','proto_leaf-1','proto_leaf-2','proto_merit-inp','proto_mfe-nsp','proto_mhrp','proto_micp','proto_mobile','proto_mtp','proto_mux','proto_narp','proto_netblt','proto_nsfnet-igp','proto_nvp','proto_ospf','proto_pgm','proto_pim','proto_pipe','proto_pnni','proto_pri-enc','proto_prm','proto_ptp','proto_pup','proto_pvp','proto_qnx','proto_rdp','proto_rsvp','proto_rtp','proto_rvd','proto_sat-expak','proto_sat-mon','proto_sccopmce','proto_scps','proto_sctp','proto_sdrp','proto_secure-vmtp','proto_sep','proto_skip','proto_sm','proto_smp','proto_snp','proto_sprite-rpc','proto_sps','proto_srp','proto_st2','proto_stp','proto_sun-nd','proto_swipe','proto_tcf','proto_tcp','proto_tlsp','proto_tp++','proto_trunk-1','proto_trunk-2','proto_ttp','proto_udp','proto_udt','proto_unas','proto_uti','proto_vines','proto_visa','proto_vmtp','proto_vrrp','proto_wb-expak','proto_wb-mon','proto_wsn','proto_xnet','proto_xns-idp','proto_xtp','proto_zero','state_ACC','state_CLO','state_CON','state_ECO','state_ECR','state_FIN','state_INT','state_MAS','state_PAR','state_REQ','state_RST','state_TST','state_TXD','state_URH','state_URN','state_no']
for feature in total_features:
    if feature not in X.columns:
        X[feature] = X.apply(lambda x:'0',axis=1)
# %%
clf = RandomForestClassifier(class_weight='balanced', verbose=1)

# %%
with open('randomforests_final2.pkl','rb') as f:
    clf = pickle.load(f)
# %%
preds = clf.predict(X)

# %%
print(accuracy_score(preds,y))
print(f1_score(preds,y))
print(recall_score(preds,y))
print(precision_score(preds,y))



# %%
