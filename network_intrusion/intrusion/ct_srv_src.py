# %%
import pandas as pd
from django.conf import settings

# %%
def get_ct_srv_src(df):
    srv_src = df[['SrcAddr', 'Proto']]
    series = []
    for index in range(len(srv_src)):
        ct_srv_src = 0
        for i in range(100):
            try:
                if srv_src.iloc[index]['SrcAddr'] == srv_src.iloc[index-i]['SrcAddr'] and srv_src.iloc[index]['Proto'] == srv_src.iloc[index-i]['Proto']:
                    ct_srv_src = ct_srv_src+1
            except Exception:
                break
        series.append(ct_srv_src)
    series = pd.Series(series,name='ct_srv_src')
    df['ct_srv_src'] = series

# %%
def get_ct_srv_dst(df):
    srv_dst = df[['DstAddr', 'Proto']]
    series = []
    for index in range(len(srv_dst)):
        ct_srv_dst = 0
        for i in range(100):
            try:
                if srv_dst.iloc[index]['DstAddr'] == srv_dst.iloc[index-i]['DstAddr'] and srv_dst.iloc[index]['Proto'] == srv_dst.iloc[index-i]['Proto']:
                    ct_srv_dst = ct_srv_dst+1
            except Exception:
                break
        series.append(ct_srv_dst)
    series = pd.Series(series,name='ct_srv_dst')
    df['ct_srv_dst'] = series

# %%
# def create_ct_state_ttl(df):
#     series = []
#     for index in enumerate(df):
#         if(df['sttl'] == 62 or df['sttl'] == 63 or df['sttl'] == 254 or df['sttl'] == 255) and (df['dttl'] == 252 or df['dttl'] == 252) and (df['state'] == 'FIN'):
#             state_ttl = 1

#         elif(df['sttl'] == 0 or df['sttl'] == 62 or df['sttl'] == 254) and (df['dttl'] == 0) and (df['state'] == 'INT'):
#             state_ttl = 2

#         elif(df['sttl'] == 62 or df['sttl'] == 254) and (df['dttl'] == 60 or df['dttl'] == 252 or df['dttl'] == 253) and (df['state'] == 'CON'):
#             state_ttl = 3

#         elif df['sttl'] == 254 and df['dttl'] == 252 and df['state'] == 'ACC':
#             state_ttl = 4

#         elif df['sttl'] == 254 and df['dttl'] == 252 and df['state'] == 'CLO':
#             state_ttl = 5

#         elif df['sttl'] == 254 and df['dttl'] == 0 and df['state'] == 'REQ':
#             state_ttl = 6

#         else:
#             state_ttl = 0

#         print(state_ttl)
#         series.append(state_ttl)

#     series = pd.Series(series, name = 'ct_state_ttl')
#     df['ct_state_ttl'] = series


# %%
# create_ct_state_ttl(df)

# get_ct_srv_dst(df)
# get_ct_srv_src(df)
# drop_col(df)

# %%


# %%


# %%
