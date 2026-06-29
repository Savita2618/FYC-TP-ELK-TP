# TP - Mise en place d'un pipeline de détection d'intrusions avec ELK et Machine Learning

**Version :** 1.0

**Création :** 06/2026

**Module :** FYC

**Auteur :** Savita BALA, Swane CAMARA

**Durée :** 3 heures

**Niveau :** M2

---

## Sommaire

1. [Introduction](#1-introduction)
2. [Partie 1 - Stack ELK](#2-partie-1---stack-elk)
3. [Partie 2 - Elastic ML](#3-partie-2---elastic-ml)
4. [Partie 3 - Pipeline Python supervisé](#4-partie-3---pipeline-python-supervisé)
5. [Mémos](#5-mémos)

---

## 1. Introduction

### 1.1. Contexte

Dans ce TP, vous allez construire une chaîne complète de détection d'intrusions, en combinant trois approches :

La stack ELK pour la collecte, le parsing et la visualisation des logs.

Elastic ML pour la détection d'anomalies non supervisée.

Un pipeline Python avec Machine Learning supervisé pour la classification des événements.

L'objectif final est d'être capable de détecter automatiquement des comportements suspects dans des journaux de connexion SSH, en comprenant les forces et limites de chaque approche.

---

### 1.2. Maquette du TP

![Maquette du TP](assets/Setup.png)

> Les deux machines peuvent être des VMs, des machines physiques ou des conteneurs selon votre environnement de travail. Les VMs fournies pour ce TP sont déjà préconfigurées et entièrement installées à votre disposition. Voir [IMPORT_VMS.md](IMPORT_VMS.md)

---

### 1.3. Données disponibles

**Sur la machine ELK :**
- `/var/log/auth.log` - 50 000 logs SSH simulés (format syslog standard)
- Index Elasticsearch `ssh-logs-*` - 50 000 documents indexés

**Sur la machine ML :**
- `/home/adminml/ssh_dataset.csv` - 50 000 événements étiquetés
- `/home/adminml/auth_realistic.log` - logs bruts correspondants
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
IPs internes légitimes  : 192.168.1.50 - 192.168.1.75 - 10.0.0.25 - 192.168.1.100
IPs externes légitimes  : 82.64.12.33 - 90.112.45.67
IPs attaquantes connues : 185.220.101.45 - 42.96.145.33 - 165.232.189.42
                          103.45.67.89  - 159.89.166.45 - 45.142.212.61
```

---

> Une fois les deux VMs importées et les cartes réseau configurées, on commence par vérifier les services de la stack ELK et par comprendre chaque fichier de configuration. Cette étape est essentielle avant de passer à la suite.

---

## 2. Partie 1 - Stack ELK

### 2.1. Vérification des services

Connectez-vous sur la machine ELK. Vérifiez que les quatre services sont actifs :

```bash
sudo systemctl status elasticsearch kibana logstash filebeat --no-pager | grep Active
```

Les 4 services doivent afficher le statut `active (running)`.

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

Filebeat contient trois sections : `filebeat.inputs`, `fields`, `output.logstash`.

---

### 2.3. Pipeline Logstash - Parsing Grok

Affichez le fichier de configuration du pipeline Logstash :

```bash
sudo cat /etc/logstash/conf.d/ssh-pipeline.conf
```

Le pipeline comporte trois blocs : `input`, `filter`, `output`.

Le filtre Grok extrait les champs d'une ligne de log SSH standard :

```
Jan 15 03:22:17 server sshd[12453]: Failed password for root from 185.220.101.45 port 52341 ssh2
```

> Le filtre Ruby ajoute le champ `is_internal_ip` en vérifiant si l'IP source appartient aux plages privées (192.168.Y.Z, 10.X.Y.Z, 172.16.Y.Z), c'est-à-dire les adresses IP privées définies par le RFC 1918.

---

### 2.4. Dashboard Kibana

Ouvrez Kibana dans votre navigateur, accédez au dashboard et cliquez sur **SSH Security Dashboard**.

Ce dashboard contient quatre visualisations :

Les machines qui génèrent le plus de trafic apparaissent en premier. Pas de surprise : ce sont des IPs internes, ce qui est normal puisque 85% du trafic du dataset est du trafic légitime.

On retrouve en tête des noms comme `admin`, `test`, `postgres` ou `root`. C'est le signe d'une attaque par dictionnaire : les attaquants essaient les noms les plus courants en espérant qu'un compte soit resté ouvert ou mal sécurisé.

Le **pie chart des méthodes d'authentification** affiche environ 60% des connexions passent par clé publique, 40% par mot de passe. Cette proportion montre que l'authentification par mot de passe reste trop présente et augmente la d'attaque brute-force.

---

### 2.5. Requêtes DSL Elasticsearch

Accédez à **Kibana → Dev Tools** pour exécuter les requêtes suivantes.

On peut lancer des requêtes pour voir quels sont les usernames ciblés par une IP , ou suivre dans le temps les tentatives échouées sur des IPs attaquantes connues.

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

## 3. Partie 2 - Elastic ML

### 3.1. Job de détection d'anomalies

Accédez à **Kibana → Machine Learning → Anomaly Detection → Jobs**.

Le job `ssh-brute-force-detection` surveille le nombre de connexions par IP toutes les 5 minutes. Il apprend ce qui est "normal" pour chaque IP, puis génère un score entre 0 et 100 dès qu'une activité s'en écarte.


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

Les entrées avec `src_ip` vide correspondent aux événements système locaux comme cron, systemd, PAM est qui n'ont pas d'IP source. Logstash ne peut pas extraire le champ, il reste vide. C'est du bruit de parsing pas une attaque.

Les IPs internes comme `192.168.1.50` (score 95) présentent une anomalie de type "Unexpected zero value" : l'IP était habituellement active avec environ 47 connexions par fenêtre, puis a brutalement disparu. Machine éteinte ou maintenance c'est faux positif classique.

Les IPs externes comme `194.165.16.72` (score 21) présentent une anomalie de type "6x higher", activité 6 fois supérieure à la normale. Score faible mais signal réellement suspect.

Un score élevé n'est pas synonyme d'attaque. Il faut toujours lire la description et remettre le score dans son contexte.

---

### 3.3. Seuils et limites

Seuils d'action recommandés pour le score d'anomalie :

| Plage de score | Action |
|---|---|
| 25 à 50 | Investigation manuelle |
| 50 à 75 | Alerte automatique SIEM |
| 75 à 100 | Blocage automatique |

Elastic ML ne fait pas la différence entre une absence malveillante et une absence légitime. Il ne peut pas être utilisé seul en production - il doit être croisé avec d'autres sources, notamment le pipeline Python supervisé.

---

## 4. Partie 3 - Pipeline Python supervisé

Connectez-vous sur la machine ML et activez l'environnement Python :

```bash
source /home/adminml/fyc-ml/bin/activate
```

---

### 4.1. Exploration du dataset

Une fois l'environnement Python activé, créez un fichier `explore_dataset.py`, copiez-collez le code suivant, puis exécutez-le pour charger le fichier `ssh_dataset.csv` :

```python
import pandas as pd
df = pd.read_csv('/home/adminml/ssh_dataset.csv')
print(df.head())
print(df.describe())
print(df['label'].value_counts())
print(f"Taux d'attaque : {df['label'].mean()*100:.1f}%")
```

Vous verrez que ce dataset contient environ 50 000 événements avec un taux d'attaque de 7% (3 500 attaques, 46 500 normaux). Ce déséquilibre est typique des données de sécurité réelles et nécessite un traitement spécifique avant l'entraînement.

---

### 4.2. Feature Engineering

Jetons maintenant un coup d'œil au script `ml_pipeline.py`. C'est ici qu'on transforme les données brutes en variables utilisables par les algorithmes.

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

Découpage train/test (70%/30%) :

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

Exécutez le script :

```bash
python3 /home/adminml/ml_pipeline.py
```

Sur la sortie du terminal, observez la section `[4/6]` qui présente les résultats des trois modèles entraînés.

---

**Comment fonctionnent ces trois modèles ?**

**Régression Logistique** - C'est le modèle le plus simple. Il cherche une frontière linéaire (une droite ou un hyperplan) qui sépare les connexions normales des attaques dans l'espace des features. Si un événement tombe d'un côté de la frontière, il est classé normal ; de l'autre côté, attaque. Son avantage est sa rapidité et son interprétabilité. Sa limite : il suppose que la séparation entre les classes est linéaire, ce qui n'est pas toujours le cas en réalité.

**Random Forest** - C'est un ensemble de 100 arbres de décision entraînés indépendamment, chacun sur un sous-ensemble aléatoire des données et des features. Chaque arbre vote pour une classe, et la majorité l'emporte. Le fait de combiner plusieurs arbres imparfaits produit un modèle global robuste et précis. Il gère bien les relations non-linéaires et est résistant au surapprentissage.

**XGBoost** - C'est un algorithme de gradient boosting. Contrairement au Random Forest où les arbres sont construits en parallèle, ici ils sont construits en séquence. Chaque nouvel arbre se concentre sur les erreurs commises par les arbres précédents et cherche à les corriger. Le résultat est un modèle très performant, surtout sur des données tabulaires comme les nôtres, avec un temps d'entraînement très court.

---

| Modèle | Temps (s) | AUC-ROC |
|---|---|---|
| Régression Logistique | 0.16 | 0.9996 |
| Random Forest | 1.34 | 1.0000 |
| XGBoost | 0.17 | 1.0000 |

Le **recall** est la métrique prioritaire : en fait, manquer une vraie attaque est plus dangereux qu'avoir un faux positif.

Les AUC très élevées s'expliquent par la nature synthétique du dataset. En production réelle, les AUC se situeraient entre 0.92 et 0.97.

---

### 4.5. Prédiction en temps réel

Réexécutez le script pour observer la prédiction sur un événement fictif présentant les caractéristiques suivantes :

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

Le modèle retourne une probabilité d'attaque de 77% pour cet événement (3h du matin, IP externe, échec, authentification par mot de passe). Décision : ALERTER - investigation requise.

---

### 4.6. Tableau comparatif ELK ML vs Python ML

| Critère | Elastic ML | Python ML supervisé |
|---|---|---|
| Type d'apprentissage | Non supervisé | Supervisé |
| Données d'étiquetage requises | Non | Oui |
| Détection d'attaques inconnues | Oui | Non |
| Classification d'attaques connues | Partielle | Oui |
| Facilité de mise à jour | Automatique | Réentraînement requis |
| Interprétabilité | Score uniquement | Probabilité + feature importance |

Dans un SOC réel, les deux approches se combinent en pipeline, Elastic ML détecte les comportements anormaux, y compris les attaques inconnues, tandis que Python ML prend le relais pour classifier rapidement les patterns connus et leur associer une probabilité chiffrée.

---

## 5. Mémos

### 5.1. Commandes Linux utiles

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

### 5.2. Elasticsearch - Requêtes DSL

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

### 5.3. Kibana - Navigation rapide

| Fonctionnalité | Chemin |
|---|---|
| Explorer les logs | Discover |
| Créer une visualisation | Visualize Library → Create |
| Accéder à Elastic ML | Machine Learning → Anomaly Detection |
| Dev Tools | Management → Dev Tools |

---

*FYC - M2 - 2025/2026*
