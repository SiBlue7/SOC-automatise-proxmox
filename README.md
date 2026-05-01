# SOC Dashboard - Proxmox Sentinel

POC de SOC automatise pour un lab Proxmox VE. L'application supervise un noeud Proxmox, liste les VM QEMU, detecte des anomalies simples sur les metriques CPU/RAM, persiste les alertes en SQLite et permet une reponse active controlee par analyste sur l'interface `net0`.

## Objectif du POC

Le projet sert de support a un memoire de Master Cybersecurite sur l'apport de l'automatisation dans la detection et la reaction face a des anomalies comportementales sur une infrastructure virtualisee.

L'approche reste volontairement progressive :

- collecte agentless via l'API Proxmox ;
- detection explicable par regles, scores et correlation simple ;
- priorisation des alertes pour limiter la surcharge analyste ;
- reponse active human-in-the-loop ;
- journalisation des preuves pour mesurer MTTD et MTTR.

## Architecture

- `app.py` : interface Streamlit, visualisation et reponse active.
- `collector.py` : collecte continue independante du navigateur.
- `ssh_log_collector.py` : collecte optionnelle des logs SSH des VM cibles.
- `config.py` : lecture et validation du `.env`.
- `proxmox_client.py` : connexion API et collecte Proxmox.
- `detection.py` : regles d'alertes, score et severite.
- `actions.py` : isolement/restauration QEMU `net0`.
- `storage.py` : persistance SQLite des metriques, alertes, actions et evenements SSH.

Le perimetre de reponse active est limite aux VM QEMU et a l'interface `net0`. Les LXC ne sont pas modifies par ce POC.

## Configuration

Copier le modele :

```powershell
Copy-Item .env.example .env
```

Variables principales :

```env
PROXMOX_HOST=192.168.1.10
PROXMOX_USER=soc-dashboard@pve
PROXMOX_TOKEN_ID=soc-dashboard-token
PROXMOX_SECRET=replace-with-your-api-token-secret
VERIFY_SSL=False
SOC_DB_PATH=/data/soc_dashboard.sqlite3
PROTECTED_VMIDS=
ALERT_HOST_CPU_WARN=80
ALERT_HOST_CPU_CRITICAL=95
ALERT_VM_CPU_WARN=80
ALERT_VM_CPU_CRITICAL=95
ALERT_VM_RAM_WARN=85
ALERT_VM_RAM_CRITICAL=95
ALERT_MIN_DURATION_SECONDS=0
MAX_HISTORY_POINTS=30
COLLECT_INTERVAL_SECONDS=5
APP_PERSIST_ON_RENDER=False
COLLECTOR_HEARTBEAT_SECONDS=30
SSH_LOG_TARGETS=103:192.168.1.139:demo-user:/var/log/auth.log
SSH_KEY_PATH=/ssh_keys/soc_dashboard_key
SSH_CONNECT_TIMEOUT_SECONDS=5
SSH_LOG_LOOKBACK_MINUTES=10
SSH_LOG_MAX_LINES=300
SSH_AUTH_FAILURE_WARN=5
SSH_AUTH_FAILURE_CRITICAL=20
SSH_CORRELATION_CPU_THRESHOLD=50
SSH_CORRELATION_WINDOW_SECONDS=300
```

`PROTECTED_VMIDS` accepte une liste separee par virgules, par exemple `100,101`. Ces VM ne peuvent pas etre isolees depuis le dashboard.

`COLLECT_INTERVAL_SECONDS` pilote la frequence de collecte du backend. `APP_PERSIST_ON_RENDER=False` evite que Streamlit double les ecritures du collecteur.

`SSH_LOG_TARGETS` active la correlation SSH. Format : `vmid:ip:user[:log_path]`, avec plusieurs cibles separees par `;`.

Le collecteur utilise une cle SSH montee depuis `./ssh_keys`. Cree une cle dediee sur la VM dashboard puis ajoute sa cle publique dans `~demo-user/.ssh/authorized_keys` sur la VM cible :

```bash
mkdir -p ssh_keys
ssh-keygen -t ed25519 -f ssh_keys/soc_dashboard_key -N ""
ssh-copy-id -i ssh_keys/soc_dashboard_key.pub demo-user@192.168.1.139
chmod 600 ssh_keys/soc_dashboard_key
```

L'utilisateur cible doit pouvoir lire les logs SSH. Selon la distribution, ajoute-le au groupe `adm` :

```bash
sudo usermod -aG adm demo-user
```

## Lancement Docker

```powershell
docker compose up --build -d
```

Verifier les services :

```powershell
docker compose ps
docker compose logs -f proxmox-collector
```

Interface :

```text
http://localhost:8501
```

La base SQLite est montee dans `./data` via Docker Compose pour conserver les preuves apres redemarrage du conteneur.

Le service `proxmox-collector` continue de collecter meme si aucune page Streamlit n'est ouverte. Le dashboard affiche son etat dans la sidebar.

## Fonctionnalites

- Vue globale du noeud Proxmox : CPU, RAM, SWAP.
- Inventaire des VM QEMU.
- Graphiques quasi temps reel pour l'hote et les VM.
- Moteur d'alertes configurable :
  - CPU host ;
  - CPU VM ;
  - RAM VM ;
  - echecs SSH ;
  - correlation echecs SSH + CPU ;
  - duree minimale avant alerte ;
  - score d'anomalie et severite faible/moyen/critique.
- Vue `Incidents / Alertes` :
  - filtres par noeud, VM, severite et statut ;
  - timeline d'incident ;
  - indicateurs MTTD, MTTR, volume d'alertes et actions.
- Reponse active :
  - confirmation explicite avant isolement ;
  - blocage des VM protegees ;
  - journal d'audit des actions ;
  - restauration reseau.
- Correlation SSH :
  - collecte des echecs SSH depuis la VM cible ;
  - alerte `ssh_bruteforce_suspected` si les echecs depassent le seuil ;
  - alerte `ssh_cpu_correlated` si les echecs SSH coincident avec une pression CPU ;
  - onglet `Logs SSH` pour auditer les evenements collectes.

## Protocole experimental

Scenario reproductible pour une demonstration de soutenance avec collecte continue :

1. Demarrer Docker Compose et verifier que `proxmox-collector` tourne.
2. Laisser le collecteur tourner sans attaque pour obtenir une baseline.
3. Ouvrir Streamlit pour controler l'etat du collecteur et les metriques.
4. Selectionner une VM QEMU cible non protegee.
5. Generer une charge CPU controlee sur la VM cible.
6. Observer l'apparition de l'alerte dans `Supervision` puis `Incidents / Alertes`.
7. Lancer un brute-force SSH controle pour verifier la correlation logs.
8. Noter le score, la severite et l'horodatage de detection.
9. Confirmer l'isolement dans `Reponse active` si le scenario le demande.
10. Verifier que `net0` passe en etat isole.
11. Restaurer le reseau.
12. Utiliser la timeline, les logs SSH et le journal d'audit comme preuve experimentale.

Exemple Linux pour generer une charge CPU de demonstration dans une VM de test :

```bash
yes > /dev/null
pkill yes
```

## Analyse des donnees

Le fichier `experiment_log.csv` sert a documenter manuellement les fenetres de test. Il permet de relier les metriques SQLite a la verite terrain : baseline, charge legitime, scan Nmap, brute-force SSH, scenario mixte.

Generer les figures :

```powershell
python analysis/generate_figures.py --db data/soc_dashboard.sqlite3 --log experiment_log.csv --out analysis_output
```

Ou via Docker, sans installer Python/Matplotlib sur l'hote :

```powershell
docker compose up -d --build
docker compose run --rm proxmox-soc python analysis/generate_figures.py --db /data/soc_dashboard.sqlite3 --log experiment_log.csv --out analysis_output
```

Forcer une VM cible precise :

```powershell
python analysis/generate_figures.py --db data/soc_dashboard.sqlite3 --log experiment_log.csv --out analysis_output --vmid 103
```

Sorties :

- `analysis_output/01_cpu_timeline.png` : CPU VM avec fenetres experimentales.
- `analysis_output/02_alerts_timeline.png` : alertes par score et severite.
- `analysis_output/03_alerts_by_scenario.png` : alertes par scenario.
- `analysis_output/04_confusion_matrix.png` : vrais positifs, faux positifs, vrais negatifs, faux negatifs.
- `analysis_output/05_mttd_mttr.png` : delais detection/reponse.
- `analysis_output/06_cpu_normal_vs_attack.png` : distribution CPU par scenario.
- `analysis_output/07_ssh_events_timeline.png` : evenements SSH et alertes correlees.
- `analysis_output/summary_results.md` : synthese prete a reprendre dans le memoire.

## Justification academique

- Pitkar (2025) soutient l'interet de l'automatisation pour coordonner detection et reponse dans des environnements cloud.
- Iacovazzi et Raza (2023) motive l'evolution future vers des modeles de type Isolation Forest lorsque l'historique sera suffisant.
- Lee et al. (2022), SIERRA, inspire la priorisation par score/severite afin d'aider l'analyste.
- Jindal et al. (2021), IAD, soutient l'interet d'une detection indirecte a partir des metriques de ressources VM/hyperviseur.

## Limites actuelles

- Detection par seuils explicables, pas encore par apprentissage automatique.
- Polling API regulier, pas d'architecture event-driven.
- Correlation SSH initiale disponible, mais limitee aux logs accessibles par SSH.
- Pas de detection reseau profonde.
- Pas de remediations autonomes completes : l'analyste valide l'isolement.
- Lab uniquement avec `VERIFY_SSL=False`; a corriger pour une production.
