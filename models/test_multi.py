# %%
import numpy as np
from sklearn.metrics import accuracy_score, precision_score, recall_score, f1_score, confusion_matrix
import pandas as pd
import pickle
from sklearn.ensemble import RandomForestClassifier, GradientBoostingClassifier
from sklearn.model_selection import train_test_split, cross_validate
from sklearn.metrics import accuracy_score, precision_score, recall_score, f1_score, make_scorer
from sklearn.ensemble import RandomForestClassifier
from sklearn.multiclass import OneVsRestClassifier

# %%
df = pd.read_csv('pcaps/UNSW_NB15_testing-set.csv')
# %%
df['attack_cat'].fillna('Normal', inplace=True)
df = df[df['attack_cat'] != 'Normal']
df['attack_cat'] = df['attack_cat'].apply(lambda x: x.strip())
df['attack_cat'].replace(to_replace='Exploits', value='DoS', inplace=True)
df['attack_cat'].replace(to_replace='Fuzzers', value='DoS', inplace=True)
df['attack_cat'].replace(to_replace='Reconnaissance',
                         value='Port Scan', inplace=True)
df['attack_cat'].replace(to_replace='Analysis',
                         value='Port Scan', inplace=True)
df['attack_cat'].replace(to_replace='Backdoors',
                         value='Privilege Escalation', inplace=True)
df['attack_cat'].replace(to_replace='Backdoor',
                         value='Privilege Escalation', inplace=True)
df['attack_cat'].replace(to_replace='Shellcode',
                         value='Privilege Escalation', inplace=True)
df['attack_cat'].replace(
    to_replace='Worms', value='Privilege Escalation', inplace=True)
# %%
X = df.drop(columns='attack_cat')
X = df[['proto', 'spkts', 'dpkts', 'tcprtt', 'state', 'dur', 'sbytes',
        'dbytes', 'ct_srv_src', 'ct_srv_dst']]  # 'sport','dsport','ct_state_ttl'
X = pd.get_dummies(X, columns=['proto', 'state'])

# %%
y = df['attack_cat']
y = y.apply(lambda x: x.strip())
y = pd.get_dummies(y)
# %%
with open('att_classes.pkl', 'rb') as f:
    mul_clf = pickle.load(f)
# %%
preds = mul_clf.predict(X)
accuracy_score(preds, y)

# %%
scores = cross_validate(mul_clf, X, y, cv=5, scoring=['accuracy'])
print(scores.keys())

# %%
print(scores['test_accuracy'])
