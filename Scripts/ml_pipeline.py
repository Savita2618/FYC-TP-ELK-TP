#!/usr/bin/env python3

import pandas as pd
import numpy as np
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import StandardScaler, LabelEncoder
from sklearn.linear_model import LogisticRegression
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import classification_report, roc_auc_score, roc_curve
from xgboost import XGBClassifier
from imblearn.over_sampling import SMOTE
import matplotlib.pyplot as plt
import time
import warnings

warnings.filterwarnings('ignore')

print("=" * 60)
print("PIPELINE ML — DÉTECTION D'INTRUSIONS SSH")
print("=" * 60)

print("\n[1/6] Chargement du dataset...")
df = pd.read_csv('/home/adminml/ssh_dataset.csv')

print(df.head())
print(df.describe())
print(df.isnull().sum())
print(df['label'].value_counts())
print(f"Taux d'attaque : {df['label'].mean()*100:.1f}%")

print("\n[2/6] Feature Engineering...")

df['timestamp'] = pd.to_datetime(df['timestamp'])
df['hour'] = df['timestamp'].dt.hour

df['is_night'] = ((df['hour'] >= 0) & (df['hour'] <= 6)).astype(int)
df['is_failed'] = (df['result'] == 'Failed').astype(int)

def is_internal(ip):
    return int(str(ip).startswith(('192.168.', '10.', '172.')))

df['is_internal'] = df['src_ip'].apply(is_internal)
df['is_password_auth'] = (df['auth_method'] == 'password').astype(int)

le_user = LabelEncoder()
le_ip = LabelEncoder()
df['username_enc'] = le_user.fit_transform(df['username'])
df['src_ip_enc'] = le_ip.fit_transform(df['src_ip'])

features = [
    'hour', 'is_night', 'is_failed', 'is_internal',
    'is_password_auth', 'src_port', 'username_enc', 'src_ip_enc'
]

X = df[features]
y = df['label']

print(f"Features sélectionnées : {features}")
print(f"Shape X : {X.shape}, Shape y : {y.shape}")

print("\n[3/6] Preprocessing...")

X_train, X_test, y_train, y_test = train_test_split(
    X, y, test_size=0.30, random_state=42, stratify=y
)

print(f"Train : {len(X_train)} exemples | Test : {len(X_test)} exemples")
print(f"Attaques dans train : {y_train.sum()} ({y_train.mean()*100:.1f}%)")

print("\nApplication de SMOTE pour rééquilibrer les classes...")
smote = SMOTE(random_state=42)
X_train_bal, y_train_bal = smote.fit_resample(X_train, y_train)
print(f"Après SMOTE — Train : {len(X_train_bal)} | Attaques : {y_train_bal.sum()}")

scaler = StandardScaler()
X_train_scaled = scaler.fit_transform(X_train_bal)
X_test_scaled = scaler.transform(X_test)

print("\n[4/6] Entraînement des modèles...")

models = {
    "Régression Logistique": LogisticRegression(max_iter=1000, random_state=42),
    "Random Forest": RandomForestClassifier(n_estimators=100, random_state=42),
    "XGBoost": XGBClassifier(n_estimators=100, random_state=42, eval_metric='logloss')
}

results = {}

for name, model in models.items():
    print(f"\n--- {name} ---")
    start = time.time()
    model.fit(X_train_scaled, y_train_bal)
    train_time = time.time() - start

    y_pred = model.predict(X_test_scaled)
    y_proba = model.predict_proba(X_test_scaled)[:, 1]

    auc = roc_auc_score(y_test, y_proba)

    print(f"Temps d'entraînement : {train_time:.2f}s")
    print(f"AUC-ROC : {auc:.4f}")
    print(classification_report(y_test, y_pred, target_names=['Normal', 'Attaque']))

    results[name] = {
        'model': model,
        'y_pred': y_pred,
        'y_proba': y_proba,
        'auc': auc,
        'train_time': train_time
    }

print("\n[5/6] Génération des courbes ROC...")

plt.figure(figsize=(10, 7))

for name, res in results.items():
    fpr, tpr, _ = roc_curve(y_test, res['y_proba'])
    plt.plot(fpr, tpr, linewidth=2, label=f"{name} (AUC = {res['auc']:.3f})")

plt.plot([0, 1], [0, 1], 'k--', linewidth=1, label='Random')
plt.xlabel('Taux de Faux Positifs', fontsize=12)
plt.ylabel('Taux de Vrais Positifs', fontsize=12)
plt.title("Courbes ROC — Comparaison des modèles\nDétection d'intrusions SSH", fontsize=14)
plt.legend(loc='lower right', fontsize=11)
plt.grid(True, alpha=0.3)
plt.tight_layout()
plt.savefig('/home/adminml/roc_curves.png', dpi=150)
print("Courbe ROC sauvegardée : /home/adminml/roc_curves.png")

print("\n[6/6] Importance des features (Random Forest)...")

rf_model = results["Random Forest"]["model"]
importances = pd.Series(rf_model.feature_importances_, index=features)
importances_sorted = importances.sort_values(ascending=True)

plt.figure(figsize=(10, 6))
importances_sorted.plot(kind='barh', color='steelblue')
plt.title('Importance des Features — Random Forest', fontsize=14)
plt.xlabel('Importance (Gini)', fontsize=12)
plt.tight_layout()
plt.savefig('/home/adminml/feature_importance.png', dpi=150)
print("Feature importance sauvegardée : /home/adminml/feature_importance.png")

print(importances.sort_values(ascending=False).head(5))

print("\n--- TEST : Prédiction en temps réel ---")

new_event = pd.DataFrame([{
    'hour': 3,
    'is_night': 1,
    'is_failed': 1,
    'is_internal': 0,
    'is_password_auth': 1,
    'src_port': 52341,
    'username_enc': 0,
    'src_ip_enc': 0
}])

new_event_scaled = scaler.transform(new_event)
best_model = results["Random Forest"]["model"]
proba = best_model.predict_proba(new_event_scaled)[0][1]

print(f"Probabilité d'attaque : {proba:.2%}")

if proba > 0.85:
    decision = "BLOQUER — Attaque très probable"
elif proba > 0.60:
    decision = "ALERTER — Investigation requise"
else:
    decision = "ACCEPTER — Connexion normale"

print(f"Décision : {decision}")

print("\n" + "=" * 60)
print("Pipeline terminé avec succès.")
print("Fichiers générés :")
print("  /home/adminml/roc_curves.png")
print("  /home/adminml/feature_importance.png")
print("=" * 60)
