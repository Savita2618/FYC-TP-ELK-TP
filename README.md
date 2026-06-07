# FYC - Pipeline de détection d'intrusions SSH

**Module :** Cybersécurité 5ème année ESGI  
**Année :** 2025 - 2026

## Contenu du repo

| Fichier | Description |
|---|---|
| `TP_Detection_ELK_ML_Sujet.md` | Sujet du TP |
| `CORRECTION_TP_Detection_ELK_ML.md` | Correction complète |
| `FYC_Script_Video_TP_Corrige.md` | Scripts oraux des vidéos |
| `ml_pipeline.py` | Pipeline ML supervisé (LR / RF / XGBoost) |
| `generate_realistic.py` | Générateur de dataset SSH |
| `optimize_rf.py` | Optimisation GridSearchCV |
| `assets/` | Diagrammes et captures |

## Infrastructure

- **VM1 - elk-stack** : Ubuntu 24.04 / ELK 8.x / Filebeat + Logstash + Elasticsearch + Kibana
- **VM2 - ml-python** : Ubuntu 24.04 / Python 3.12 / scikit-learn / XGBoost / imbalanced-learn

Les images des VMs (VMDK) sont disponibles ici : **[https://reseauges75-my.sharepoint.com/:f:/g/personal/s_bala_myskolae_fr/IgDfPLAtK3pxQ6iYY0JfAbY4AYkoV-26e0sBwihwkCyXN68?e=7FsEw1]**  

→ Voir [IMPORT_VMS.md](IMPORT_VMS.md) pour les importer dans VirtualBox ou VMware.

## Résultats obtenus

| Modèle | AUC-ROC | F1-score |
|---|---|---|
| Régression Logistique | 0.9996 | 0.92 |
| Random Forest | 1.0000 | 0.97 |
| XGBoost | 1.0000 | 0.98 |

Dataset : 50 000 événements SSH - 7% d'attaques - SMOTE appliqué sur le train set.
