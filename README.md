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
- `syslog_collector.py` : reception centralisee des logs SSH/auth envoyes par les VM.
- `ssh_log_collector.py` : fallback optionnel par connexion SSH, desactive par defaut.
- `auth_log_parser.py` : parsing commun des evenements SSH.
- `incident_engine.py` : regroupement des alertes en incidents correles.
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
SYSLOG_ENABLED=True
SYSLOG_BIND_HOST=0.0.0.0
SYSLOG_PORT=5514
SYSLOG_PROTOCOLS=tcp,udp
SYSLOG_DEFAULT_NODE=pve
SYSLOG_VM_MAP=103:192.168.1.139:demo-target
SSH_LOG_TARGETS=
SSH_KEY_PATH=
SSH_CONNECT_TIMEOUT_SECONDS=5
SSH_LOG_LOOKBACK_MINUTES=10
SSH_LOG_MAX_LINES=300
SSH_AUTH_FAILURE_WARN=5
SSH_AUTH_FAILURE_CRITICAL=20
SSH_SOURCE_FAILURE_WARN=5
SSH_DISTRIBUTED_SOURCE_WARN=3
SSH_SUCCESS_AFTER_FAILURE_WARN=3
SSH_CORRELATION_CPU_THRESHOLD=50
SSH_CORRELATION_WINDOW_SECONDS=300
```

`PROTECTED_VMIDS` accepte une liste separee par virgules, par exemple `100,101`. Ces VM ne peuvent pas etre isolees depuis le dashboard.

`COLLECT_INTERVAL_SECONDS` pilote la frequence de collecte du backend. `APP_PERSIST_ON_RENDER=False` evite que Streamlit double les ecritures du collecteur.

`SYSLOG_VM_MAP` active la correlation SSH durable. Format : `vmid:host[:name[:node]]`, avec plusieurs VM separees par `;`. Exemple multi-VM :

```env
SYSLOG_VM_MAP=103:192.168.1.139:demo-target:pve;104:192.168.1.140:web-01:pve
```

`host` peut etre l'adresse IP source ou le hostname envoye par rsyslog. Si le noeud n'est pas precise, `SYSLOG_DEFAULT_NODE` est utilise.

### Configuration Syslog des VM Linux

Sur chaque VM Linux surveillee, installer et configurer rsyslog pour pousser les logs auth vers le SOC :

```bash
sudo apt install rsyslog
sudo nano /etc/rsyslog.d/90-soc-dashboard.conf
```

Contenu recommande en TCP :

```text
auth,authpriv.* @@IP_DU_SOC:5514
```

Puis redemarrer rsyslog :

```bash
sudo systemctl restart rsyslog
```

En lab, ouvrir le port `5514/tcp` uniquement depuis le reseau des VM. UDP est aussi disponible avec `@IP_DU_SOC:5514`, mais TCP est recommande pour limiter les pertes.

### Fallback SSH optionnel

`SSH_LOG_TARGETS` reste disponible pour debug ou environnement sans rsyslog. Format : `vmid:ip:user[:log_path]`, avec plusieurs cibles separees par `;`. Ce mode necessite une cle SSH montee depuis `./ssh_keys` et un utilisateur pouvant lire `/var/log/auth.log`. Il est desactive par defaut car moins perenne.

## Lancement Docker

```powershell
docker compose up --build -d
```

Verifier les services :

```powershell
docker compose ps
docker compose logs -f proxmox-collector
docker compose logs -f soc-syslog
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
  - incidents correles avec statuts `open`, `acknowledged`, `contained`, `resolved` ;
  - filtres par noeud, VM, severite et statut ;
  - timeline d'incident ;
  - indicateurs MTTD, MTTR, volume d'alertes et actions.
- Reponse active :
  - confirmation explicite avant isolement ;
  - blocage des VM protegees ;
  - journal d'audit des actions ;
  - restauration reseau.
- Correlation SSH :
  - collecte des echecs SSH via Syslog centralise ;
  - alerte `ssh_bruteforce_suspected` si les echecs depassent le seuil ;
  - alerte `ssh_bruteforce_source` si une meme IP source depasse le seuil ;
  - alerte `ssh_bruteforce_distributed` si plusieurs sources attaquent la meme VM ;
  - alerte `ssh_success_after_failures` si une connexion reussit apres des echecs ;
  - alerte `ssh_cpu_correlated` si les echecs SSH coincident avec une pression CPU ;
  - onglet `Logs SSH / Syslog` pour auditer les evenements collectes.

## Incident Engine

Le moteur d'incidents regroupe les alertes proches dans un objet exploitable par l'analyste :

- `ssh_intrusion` : brute-force, brute-force par source, brute-force distribue, succes apres echecs, correlation SSH/CPU.
- `resource_pressure` : pression CPU/RAM sur une VM.
- `host_pressure` : pression ressources sur le noeud Proxmox.

Les incidents sont crees automatiquement par `proxmox-collector`, puis visibles dans `Incidents / Alertes`. L'analyste peut les passer en :

- `open` : incident detecte, pas encore traite ;
- `acknowledged` : incident vu et pris en compte ;
- `contained` : action de confinement realisee ou en cours ;
- `resolved` : incident clos.

Cette couche reduit la surcharge analyste : plusieurs alertes techniques peuvent etre lues comme un seul incident coherent.

## Protocole experimental

Scenario reproductible pour une demonstration de soutenance avec collecte continue :

1. Demarrer Docker Compose et verifier que `proxmox-collector` tourne.
2. Laisser le collecteur tourner sans attaque pour obtenir une baseline.
3. Ouvrir Streamlit pour controler l'etat du collecteur et les metriques.
4. Selectionner une VM QEMU cible non protegee.
5. Generer une charge CPU controlee sur la VM cible.
6. Observer l'apparition de l'alerte dans `Supervision` puis `Incidents / Alertes`.
7. Lancer un brute-force SSH controle pour verifier la correlation Syslog.
8. Noter le score, la severite et l'horodatage de detection.
9. Verifier la creation d'un incident `ssh_intrusion`.
10. Passer l'incident en `acknowledged`.
11. Confirmer l'isolement dans `Reponse active` si le scenario le demande.
12. Passer l'incident en `contained`, verifier que `net0` passe en etat isole.
13. Restaurer le reseau, puis passer l'incident en `resolved`.
14. Utiliser la timeline, les logs SSH et le journal d'audit comme preuve experimentale.

Exemple Linux pour generer une charge CPU de demonstration dans une VM de test :

```bash
yes > /dev/null
pkill yes
```

## Analyse des donnees

Le fichier `experiment_log.csv` sert a documenter manuellement les fenetres de test. Il permet de relier les metriques SQLite a la verite terrain : baseline, charge legitime, scan Nmap, brute-force SSH, scenario mixte.

Les heures du fichier sont notees en heure locale Europe/Paris. Le script les convertit automatiquement vers l'UTC utilise par les conteneurs Docker pour aligner correctement les graphiques.

Generer les figures :

```powershell
python analysis/generate_figures.py --db data/soc_dashboard.sqlite3 --log experiment_log.csv --out analysis_output
```

Ou via Docker, sans installer Python/Matplotlib sur l'hote :

```powershell
docker compose up -d --build
docker compose run --rm proxmox-soc python analysis/generate_figures.py --db /data/soc_dashboard.sqlite3 --log experiment_log.csv --out analysis_output
```

Pour distinguer la campagne Syslog du jour des premieres figures, ajoute un prefixe date :

```powershell
docker compose run --rm proxmox-soc python analysis/generate_figures.py --db /data/soc_dashboard.sqlite3 --log experiment_log.csv --out analysis_output --vmid 103 --filename-prefix 2026-05-01_syslog_
```

Forcer une VM cible precise :

```powershell
python analysis/generate_figures.py --db data/soc_dashboard.sqlite3 --log experiment_log.csv --out analysis_output --vmid 103
```

Si tu notes un futur journal directement en UTC, ajoute `--experiment-timezone UTC`.

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
- Correlation SSH disponible via Syslog, sans lecture distante repetitive des VM.
- Pas encore de chiffrement TLS Syslog dans le POC ; a securiser par firewall/reseau prive en lab.
- Pas de detection reseau profonde.
- Pas de remediations autonomes completes : l'analyste valide l'isolement.
- Lab uniquement avec `VERIFY_SSL=False`; a corriger pour une production.
