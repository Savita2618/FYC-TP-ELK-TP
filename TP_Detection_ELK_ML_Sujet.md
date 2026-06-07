# TP — Mise en place d'un pipeline de détection d'intrusions avec ELK et Machine Learning

**Version :** 1.0 &nbsp;&nbsp;&nbsp;&nbsp; **Création :** 06/2026 &nbsp;&nbsp;&nbsp;&nbsp; **Module :** FYC — Cybersécurité 5ème année

**Auteur :** Kaj Backup &nbsp;&nbsp;&nbsp;&nbsp; **Durée :** 4 heures &nbsp;&nbsp;&nbsp;&nbsp; **Niveau :** Mastère Cybersécurité

---

## Sommaire

1. [Introduction](#1-introduction)
2. [Partie 1 — Stack ELK](#2-partie-1--stack-elk)
3. [Partie 2 — Elastic ML](#3-partie-2--elastic-ml)
4. [Partie 3 — Pipeline Python supervisé](#4-partie-3--pipeline-python-supervisé)
5. [Partie 4 — Cas pratique intégré](#5-partie-4--cas-pratique-intégré)
6. [Mémos](#6-mémos)

---

## 1. Introduction

### 1.1. Contexte

Dans ce TP, vous allez construire une chaîne complète de détection d'intrusions SSH, en combinant trois approches complémentaires :

La **stack ELK** pour la collecte, le parsing et la visualisation des logs. **Elastic ML** pour la détection d'anomalies non supervisée. Un **pipeline Python** avec Machine Learning supervisé pour la classification des événements.

L'objectif final est d'être capable de détecter automatiquement des comportements suspects dans des journaux de connexion SSH, en comprenant les forces et limites de chaque approche.

---

### 1.2. Infrastructure disponible

![Maquette du TP](assets/Setup.png)


Les deux machines peuvent être des VMs, des machines physiques ou des conteneurs selon votre environnement de travail.

---

### 1.3. Données disponibles

**Sur la machine ELK :**
- `/var/log/auth.log` — 50 000 logs SSH simulés (format syslog standard)
- Index Elasticsearch `ssh-logs-*` — 50 000 documents indexés

**Sur la machine ML :**
- `/home/adminml/ssh_dataset.csv` — 50 000 événements étiquetés
- `/home/adminml/auth_realistic.log` — logs bruts correspondants
- Environnement Python virtuel : `/home/adminml/fyc-ml/`

**Distribution du dataset :**

| Catégorie | Volume | Pourcentage |
|---|---|---|
| Connexions normales (IP interne, heures bureau) | 42 500 | 85% |
| Échecs légitimes (IP interne ou externe connue) | 4 000 | 8% |
| Attaques brute-force (IP externe, nuit) | 2 500 | 5% |
| Attaques lentes (IP externe, heures bureau) | 1 000 | 2% |

**IPs de référence :**

```
IPs internes légitimes  : 192.168.1.50 — 192.168.1.75 — 10.0.0.25 — 192.168.1.100
IPs externes légitimes  : 82.64.12.33 — 90.112.45.67
IPs attaquantes connues : 185.220.101.45 — 42.96.145.33 — 165.232.189.42
                          103.45.67.89  — 159.89.166.45 — 45.142.212.61
```

---

## 2. Partie 1 — Stack ELK

### 2.1. Vérification des services

Connectez-vous sur la machine ELK. Vérifiez que les quatre services sont actifs :

```bash
sudo systemctl status elasticsearch kibana logstash filebeat --no-pager | grep Active
```

Vérifiez que les 50 000 documents sont indexés dans Elasticsearch :

```bash
curl -s http://localhost:9200/ssh-logs-*/_count
```

---

### 2.2. Configuration Filebeat

Affichez la configuration complète de Filebeat :

```bash
sudo cat /etc/filebeat/filebeat.yml
```

---

### 2.3. Pipeline Logstash — Parsing Grok

Affichez le fichier de configuration du pipeline Logstash :

```bash
sudo cat /etc/logstash/conf.d/ssh-pipeline.conf
```

Le pipeline comporte trois blocs : `input`, `filter`, `output`.

Le filtre Grok extrait les champs d'une ligne de log SSH standard :

```
Jan 15 03:22:17 server sshd[12453]: Failed password for root from 185.220.101.45 port 52341 ssh2
```

Le filtre Ruby ajoute le champ `is_internal_ip` en vérifiant si l'IP source appartient aux plages RFC 1918 (192.168.x.x, 10.x.x.x, 172.16.x.x).

---

### 2.4. Dashboard Kibana

Ouvrez Kibana dans votre navigateur et accédez au dashboard SSH.

Le dashboard contient quatre visualisations :

La **timeline Accepted/Failed** montre l'évolution du trafic SSH dans le temps, permettant de repérer des pics d'échecs d'authentification.

Le **top des IPs sources** affiche les machines les plus actives. Les IPs internes dominent naturellement le classement — c'est cohérent avec la distribution du dataset où 85% du trafic est légitime.

Le **top des usernames ciblés** révèle les comptes les plus exposés. La présence de comptes génériques comme `admin`, `test`, `postgres` ou `root` indique des tentatives par dictionnaire.

Le **pie chart des méthodes d'authentification** affiche environ 60% `publickey` et 40% `password`. Cette proportion montre que l'authentification par mot de passe reste trop présente et augmente la surface d'attaque brute-force.

---

### 2.5. Requêtes DSL Elasticsearch

Accédez à **Kibana → Dev Tools**.

**Top usernames ciblés par une IP suspecte :**

```json
GET ssh-logs-*/_search
{
  "size": 0,
  "query": {
    "term": { "src_ip.keyword": "45.142.212.61" }
  },
  "aggs": {
    "top_usernames": {
      "terms": { "field": "username.keyword", "size": 10 }
    }
  }
}
```

**Timeline des tentatives Failed pour les IPs attaquantes connues :**

```json
GET ssh-logs-*/_search
{
  "size": 0,
  "query": {
    "bool": {
      "must": [
        { "term": { "result.keyword": "Failed" } },
        { "terms": { "src_ip.keyword": [
            "185.220.101.45", "42.96.145.33", "165.232.189.42",
            "103.45.67.89", "159.89.166.45", "45.142.212.61"
        ]}}
      ]
    }
  },
  "aggs": {
    "par_heure": {
      "date_histogram": {
        "field": "@timestamp",
        "calendar_interval": "hour"
      }
    }
  }
}
```

---

## 3. Partie 2 — Elastic ML

### 3.1. Job de détection d'anomalies

Accédez à **Kibana → Machine Learning → Anomaly Detection → Jobs**.

Le job existant `ssh-brute-force-detection` surveille le volume de connexions par IP source sur des fenêtres de 5 minutes. Elastic ML modélise la baseline de chaque entité et attribue un score d'anomalie de 0 à 100 quand un comportement s'écarte significativement de cette baseline.

| Paramètre | Valeur |
|---|---|
| Nom du job | ssh-brute-force-detection |
| Type de job | Multi-metric |
| Champ de découpage | src_ip.keyword |
| Bucket span | 5 minutes |

---

### 3.2. Anomaly Explorer

Accédez à **ML → Anomaly Explorer** et sélectionnez le job de détection.

L'Anomaly Timeline affiche les scores par IP source dans le temps. Plusieurs comportements distincts sont visibles :

Les entrées avec `src_ip` vide (score élevé) correspondent aux événements système locaux — cron, systemd, PAM — qui n'ont pas d'IP source. Logstash ne peut pas extraire le champ, il reste vide. C'est du bruit de parsing, pas une attaque.

Les IPs internes comme `192.168.1.50` (score 95) présentent une anomalie de type "Unexpected zero value" : l'IP était habituellement active avec ~47 connexions par fenêtre, puis a brutalement disparu. Machine éteinte ou maintenance — faux positif classique.

Les IPs externes comme `194.165.16.72` (score 21) présentent une anomalie de type "6x higher" : activité 6 fois supérieure à la normale. Score faible mais signal réellement suspect.

Un score élevé n'est pas synonyme d'attaque. "Higher" est suspect, "zero value" est souvent bénin. Il faut toujours lire la description et remettre le score dans son contexte.

---

### 3.3. Seuils et limites

Seuils d'action recommandés pour le score d'anomalie :

| Plage de score | Action |
|---|---|
| 25 à 50 | Investigation manuelle |
| 50 à 75 | Alerte automatique SIEM |
| 75 à 100 | Blocage automatique |

Elastic ML ne fait pas la différence entre une absence malveillante et une absence légitime. Il ne peut pas être utilisé seul en production — il doit être croisé avec d'autres sources, notamment le pipeline Python supervisé.

---

## 4. Partie 3 — Pipeline Python supervisé

Connectez-vous sur la machine ML et activez l'environnement Python :

```bash
source /home/adminml/fyc-ml/bin/activate
```

---

### 4.1. Exploration du dataset

```python
import pandas as pd
df = pd.read_csv('/home/adminml/ssh_dataset.csv')
print(df.head())
print(df.describe())
print(df['label'].value_counts())
print(f"Taux d'attaque : {df['label'].mean()*100:.1f}%")
```

Le dataset contient 50 000 événements avec un taux d'attaque de 7% (3 500 attaques, 46 500 normaux). Ce déséquilibre est typique des données de sécurité réelles et nécessite un traitement spécifique avant l'entraînement.

---

### 4.2. Feature Engineering

Les variables suivantes sont créées à partir des champs bruts :

| Variable | Description |
|---|---|
| `hour` | Heure extraite du timestamp |
| `is_night` | 1 si heure entre 0h et 6h |
| `is_failed` | 1 si résultat = `Failed` |
| `is_internal` | 1 si IP interne RFC 1918 |
| `is_password_auth` | 1 si méthode = `password` |
| `username_enc` | Encodage numérique via LabelEncoder |
| `src_ip_enc` | Encodage numérique via LabelEncoder |

Les variables textuelles `username` et `src_ip` doivent être encodées en entiers car les algorithmes ML ne traitent que des valeurs numériques.

---

### 4.3. Prétraitement et SMOTE

Découpage stratifié train/test (70%/30%) :

```python
from sklearn.model_selection import train_test_split
X_train, X_test, y_train, y_test = train_test_split(
    X, y, test_size=0.30, random_state=42, stratify=y
)
```

Le paramètre `stratify=y` garantit que les 7% d'attaques sont proportionnellement répartis dans les deux sous-ensembles.

Application de SMOTE sur le train set uniquement :

```python
from imblearn.over_sampling import SMOTE
smote = SMOTE(random_state=42)
X_train_bal, y_train_bal = smote.fit_resample(X_train, y_train)
```

SMOTE génère des exemples synthétiques en interpolant entre des attaques existantes. Il ne copie pas bêtement les exemples minoritaires. Le test set garde la distribution réelle pour des métriques honnêtes.

---

### 4.4. Entraînement et comparaison des modèles

```bash
python3 /home/adminml/ml_pipeline.py
```

| Modèle | Temps (s) | AUC-ROC |
|---|---|---|
| Régression Logistique | 0.16 | 0.9996 |
| Random Forest | 1.34 | 1.0000 |
| XGBoost | 0.17 | 1.0000 |

En cybersécurité, le **recall** est la métrique prioritaire : manquer une vraie attaque est plus dangereux qu'avoir un faux positif.

Les AUC très élevées s'expliquent par la nature synthétique du dataset. En production réelle, les AUC se situeraient entre 0.92 et 0.97.

---

### 4.5. Optimisation GridSearchCV

```bash
python3 /home/adminml/optimize_rf.py
```

La grille testée sur Random Forest :

```python
param_grid = {
    'n_estimators':      [50, 100, 200],
    'max_depth':         [10, 20, None],
    'min_samples_split': [2, 5, 10]
}
```

Meilleurs paramètres obtenus : `max_depth=20`, `min_samples_split=2`, `n_estimators=100`. F1-score CV : 0.9969. F1-score test : 0.9704.

---

### 4.6. Prédiction en temps réel

```python
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
```

Le modèle retourne une probabilité d'attaque de 77% pour cet événement (3h du matin, IP externe, échec, authentification par mot de passe). Décision : ALERTER — investigation requise.

---

## 5. Partie 4 — Cas pratique intégré

### 5.1. Analyse de l'IP suspecte 45.142.212.61

Dans Kibana Dev Tools, récupérer toutes les connexions associées à cette IP :

```json
GET ssh-logs-*/_search
{
  "size": 0,
  "query": { "term": { "src_ip.keyword": "45.142.212.61" }},
  "aggs": {
    "par_heure": {
      "date_histogram": { "field": "@timestamp", "calendar_interval": "hour" }
    },
    "usernames_cibles": {
      "terms": { "field": "username.keyword", "size": 10 }
    }
  }
}
```

---

### 5.2. Complémentarité ELK ML vs Python ML

| Critère | Elastic ML | Python ML supervisé |
|---|---|---|
| Type d'apprentissage | Non supervisé | Supervisé |
| Données d'étiquetage requises | Non | Oui |
| Détection d'attaques inconnues | Oui | Non |
| Classification d'attaques connues | Partielle | Oui |
| Facilité de mise à jour | Automatique | Réentraînement requis |
| Interprétabilité | Score uniquement | Probabilité + feature importance |

Dans un SOC réel, les deux approches coexistent en cascade : Elastic ML pour la détection du comportement anormal incluant les attaques inconnues, Python ML pour la classification rapide et la probabilité chiffrée sur les patterns connus.

---

## 6. Mémos

### 6.1. Commandes Linux utiles

```bash
# Vérifier l'état d'un service
sudo systemctl status <service>

# Afficher les logs d'un service en temps réel
sudo journalctl -u <service> -f

# Tester la connectivité vers Elasticsearch
curl -s http://localhost:9200
curl -s http://localhost:9200/_cat/indices?v

# Activer l'environnement Python virtuel
source /home/adminml/fyc-ml/bin/activate
```

---

### 6.2. Elasticsearch — Requêtes DSL

```json
GET ssh-logs-*/_count

GET ssh-logs-*/_search
{
  "query": {
    "term": { "src_ip": "45.142.212.61" }
  }
}

GET ssh-logs-*/_search
{
  "size": 0,
  "aggs": {
    "top_users": {
      "terms": { "field": "username.keyword", "size": 10 }
    }
  }
}
```

---

### 6.3. Python — rappels scikit-learn

```python
from sklearn.metrics import classification_report, roc_auc_score
print(classification_report(y_test, y_pred, target_names=['Normal', 'Attaque']))
auc = roc_auc_score(y_test, y_proba)

from imblearn.over_sampling import SMOTE
smote = SMOTE(random_state=42)
X_bal, y_bal = smote.fit_resample(X_train, y_train)

from sklearn.model_selection import GridSearchCV
gs = GridSearchCV(model, param_grid, cv=3, scoring='f1', n_jobs=-1)
gs.fit(X_train, y_train)
print(gs.best_params_)
```

---

### 6.4. Kibana — Navigation rapide

| Fonctionnalité | Chemin |
|---|---|
| Explorer les logs | Discover |
| Créer une visualisation | Visualize Library → Create |
| Accéder à Elastic ML | Machine Learning → Anomaly Detection |
| Dev Tools | Management → Dev Tools |

---

*FYC — Cybersécurité 5ème année — 2025/2026*
