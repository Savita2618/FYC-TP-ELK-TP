# Import des VMs - VirtualBox et VMware

## Téléchargement

Les deux images VMDK sont disponibles ici : **[https://reseauges75-my.sharepoint.com/:f:/g/personal/s_bala_myskolae_fr/IgDfPLAtK3pxQ6iYY0JfAbY4AYkoV-26e0sBwihwkCyXN68?e=7FsEw1]**


| Fichier | Taille | Contenu |
|---|---|---|
| `elk-stack.vmdk` | ~17 Go | Ubuntu 24.04 + ELK 8.x + 50 000 logs SSH indexés |
| `ml-python.vmdk` | ~10 Go | Ubuntu 24.04 + Python 3.12 + pipeline ML complet |

---

## VirtualBox

### Prérequis
- VirtualBox 7.x : https://www.virtualbox.org/wiki/Downloads
- RAM disponible : 8 Go minimum (4 Go pour elk-stack + 4 Go pour ml-python)

### VM1 - elk-stack

1. **Nouvelle VM** → Nom : `elk-stack` / Type : Linux / Version : Ubuntu 64-bit
2. RAM : `4096 Mo`
3. Disque : **Utiliser un fichier existant** → sélectionner `elk-stack.vmdk`
4. **Paramètres → Système → Carte mère** : décocher `Activer EFI`
5. **Paramètres → Réseau** :
   - Adaptateur 1 : NAT
   - Adaptateur 2 : Réseau hôte uniquement (Host-Only)

### VM2 - ml-python

1. **Nouvelle VM** → Nom : `ml-python` / Type : Linux / Version : Ubuntu 64-bit
2. RAM : `4096 Mo`
3. Disque : **Utiliser un fichier existant** → sélectionner `ml-python.vmdk`
4. **Paramètres → Système → Carte mère** : décocher `Activer EFI`
5. **Paramètres → Réseau** : Adaptateur 1 : NAT

### Identifiants

| VM | Login | Mot de passe |
|---|---|---|
| elk-stack | adminelk | esgi |
| ml-python | adminml | esgi |

### Correction réseau au premier démarrage

Le nom des interfaces réseau dépend de la machine hôte et peut varier. **Ne pas copier-coller les noms à l'aveugle.**

```bash
# Étape 1 - identifier les interfaces présentes
ip a
# Exemple de résultat : enp0s3, enp0s8 (VirtualBox) ou ens33, ens38 (VMware)
# Les noms réels peuvent être différents sur votre machine
```

```bash
# Étape 2 - mettre à jour netplan avec les noms exacts observés
sudo nano /etc/netplan/50-cloud-init.yaml
```

```yaml
# Remplacer INTERFACE_1 et INTERFACE_2 par les noms vus dans ip a
network:
  version: 2
  ethernets:
    INTERFACE_1:
      dhcp4: true
    INTERFACE_2:        # elk-stack uniquement (host-only)
      dhcp4: true
```

```bash
# Étape 3 — appliquer et vérifier
sudo netplan apply
ip a
# Noter l'IP de l'interface host-only — c'est l'adresse pour accéder à Kibana
```

Accès Kibana depuis le navigateur hôte : `http://[IP_host-only]:5601`

---

## VMware Workstation

### Prérequis
- VMware Workstation 17+ ou VMware Player

### Import

1. **File → Open** → sélectionner `elk-stack.vmdk`
2. VMware crée automatiquement une VM à partir du VMDK
3. Adapter la RAM : 4 Go pour elk-stack, 4 Go pour ml-python
4. **VM Settings → Network** :
   - elk-stack : deux cartes - NAT + Host-only
   - ml-python : NAT uniquement

### Identifiants

Identiques à VirtualBox - voir tableau ci-dessus.

### Correction réseau

Même procédure : lancer `ip a` au premier démarrage, noter les noms d'interfaces, puis mettre à jour netplan en conséquence.

---

## Vérification post-démarrage

```bash
# Sur elk-stack
sudo systemctl status elasticsearch kibana logstash filebeat --no-pager | grep Active
curl -s http://localhost:9200/ssh-logs-*/_count
# Attendu : {"count":50000,...}
```

```bash
# Sur ml-python
source /home/adminml/fyc-ml/bin/activate
python3 /home/adminml/ml_pipeline.py
```
