# To add a new cell, type '# %%'
# To add a new markdown cell, type '# %% [markdown]'
# %%
from sklearn.metrics import accuracy_score, precision_score, recall_score, f1_score, confusion_matrix
import matplotlib.pyplot as plt
import pickle
import numpy as np
from sklearn.model_selection import train_test_split, cross_validate
from sklearn.multiclass import OneVsRestClassifier
from sklearn.ensemble import RandomForestClassifier
import pandas as pd
features = pd.read_csv('NB15_features.csv', engine='python')
df_1 = pd.read_csv('UNSW-NB15_1.csv')
col_names = features['Name']
df_1.columns = col_names
df_2 = pd.read_csv('UNSW-NB15_2.csv')
df_2.columns = col_names
df_3 = pd.read_csv('UNSW-NB15_3.csv')
df_3.columns = col_names
df_4 = pd.read_csv('UNSW-NB15_4.csv')
df_4.columns = col_names
df = pd.concat([df_1, df_2, df_3, df_4], axis=0)
print(len(df.columns))
print(df.columns)


# %%
df['attack_cat'].fillna('Normal', inplace=True)
df['attack_cat'].head()


# %%
df = df[df['attack_cat'] != 'Normal']
df['attack_cat'] = df['attack_cat'].apply(lambda x: x.strip())
df['attack_cat'].value_counts()


# %%
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
df['attack_cat'].value_counts()


# %%
X = df.drop(columns='attack_cat')
X = df[['proto', 'Spkts', 'Dpkts', 'tcprtt', 'state', 'dur', 'sbytes',
        'dbytes', 'ct_srv_src', 'ct_srv_dst']]  # 'sport','dsport','ct_state_ttl'
y = df['attack_cat']


# %%
y = y.apply(lambda x: x.strip())


# %%
y.value_counts()


# %%
X = pd.get_dummies(X, columns=['proto', 'state'])


# %%
y = pd.get_dummies(y)


# %%
clf = RandomForestClassifier(class_weight='balanced', n_estimators=100)


# %%
mul_clf = OneVsRestClassifier(clf)


# %%
# X_train, X_test, y_train, y_test = train_test_split(X,y,test_size=0.2,random_state=1)
# mul_clf.fit(X_train,y_train)
with open('/home/kushal/att_classes.pkl', 'rb') as f:
    mul_clf = pickle.load(f)
# %%
preds = mul_clf.predict(X)
accuracy_score(preds, y)
# %%
cm = confusion_matrix(np.array(y_test).argmax(axis=1),
                      np.array(preds).argmax(axis=1))
print(cm)
plt.imshow(cm, interpolation='nearest', cmap=plt.cm.Wistia)
scores = cross_validate(mul_clf, X, y, cv=5, scoring=['accuracy'])
print(scores.keys())


# %%
scores['test_accuracy']


# %%
accuracy_score(preds, y_test)


# %%
mul_clf.fit(X, y)
with open('/kaggle/working/att_classes.pkl', 'wb') as f:
    pickle.dump(mul_clf, f)


# %%
with open('/kaggle/input/model-weight/att_classes.pkl', 'rb') as f:
    new_clf = pickle.load(f)
X_train, X_test, y_train, y_test = train_test_split(
    X, y, test_size=0.2, random_state=1)
preds = new_clf.predict(X_test)
print(preds[:10])
print(accuracy_score(preds, y_test))


# %%
# X_train, X_test, y_train, y_test = train_test_split(X,y,test_size=0.2,random_state=1)
# clf2 = RandomForestClassifier() #class_weight='balanced'
# new_clf = OneVsRestClassifier(clf2)
# new_clf.fit(X_train,y_train)
