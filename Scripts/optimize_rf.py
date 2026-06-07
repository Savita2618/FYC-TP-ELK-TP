#!/usr/bin/env python3

import pandas as pd
from sklearn.model_selection import train_test_split, GridSearchCV
from sklearn.ensemble import RandomForestClassifier
from sklearn.preprocessing import StandardScaler
from sklearn.metrics import f1_score
from imblearn.over_sampling import SMOTE
import time

df = pd.read_csv('/home/adminml/ssh_dataset.csv')
df['timestamp'] = pd.to_datetime(df['timestamp'])
df['hour'] = df['timestamp'].dt.hour
df['is_night'] = ((df['hour'] >= 0) & (df['hour'] <= 6)).astype(int)
df['is_failed'] = (df['result'] == 'Failed').astype(int)
df['is_internal'] = df['src_ip'].apply(lambda ip: int(str(ip).startswith(('192.168.','10.','172.'))))
df['is_password_auth'] = (df['auth_method'] == 'password').astype(int)

from sklearn.preprocessing import LabelEncoder
le_user = LabelEncoder()
le_ip   = LabelEncoder()
df['username_enc'] = le_user.fit_transform(df['username'])
df['src_ip_enc']   = le_ip.fit_transform(df['src_ip'])

features = ['hour','is_night','is_failed','is_internal',
            'is_password_auth','src_port','username_enc','src_ip_enc']
X = df[features]
y = df['label']

X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.3, random_state=42, stratify=y)
smote = SMOTE(random_state=42)
X_train_bal, y_train_bal = smote.fit_resample(X_train, y_train)
scaler = StandardScaler()
X_train_sc = scaler.fit_transform(X_train_bal)
X_test_sc  = scaler.transform(X_test)

param_grid = {
    'n_estimators': [50, 100, 200],
    'max_depth':    [10, 20, None],
    'min_samples_split': [2, 5, 10]
}

print("GridSearchCV en cours (peut prendre 5-10 minutes)...")
start = time.time()

gs = GridSearchCV(
    RandomForestClassifier(random_state=42),
    param_grid,
    cv=3,
    scoring='f1',
    n_jobs=-1,
    verbose=1
)
gs.fit(X_train_sc, y_train_bal)

elapsed = time.time() - start
print(f"\nTemps total : {elapsed:.1f}s")
print(f"Meilleurs paramètres : {gs.best_params_}")
print(f"Meilleur F1-score (CV) : {gs.best_score_:.4f}")

y_pred_best = gs.best_estimator_.predict(X_test_sc)
f1_test = f1_score(y_test, y_pred_best)
print(f"F1-score sur test : {f1_test:.4f}")
