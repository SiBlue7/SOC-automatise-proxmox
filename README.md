# SOC Dashboard - Proxmox Sentinel

POC de SOC automatise pour un lab Proxmox VE. L'application supervise un noeud Proxmox, liste les VM QEMU, detecte des anomalies simples sur les metriques CPU/RAM, persiste les alertes en SQLite et permet une reponse active controlee par analyste sur l'interface `net0`.

## Objectif du POC

Le projet sert de support a un memoire de Master Cybersecurite sur l'apport de l'automatisation dans la detection et la reaction face a des anomalies comportementales sur une infrastructure virtualisee.

L'approche reste volontairement progressive :

- collecte agentless via l'API Proxmox ;
- detection explicable par regles et scores ;
- priorisation des alertes pour limiter la surcharge analyste ;
- reponse active human-in-the-loop ;
- journalisation des preuves pour mesurer MTTD et MTTR.

## Architecture

- `app.py` : interface Streamlit et orchestration SOC.
- `config.py` : lecture et validation du `.env`.
- `proxmox_client.py` : connexion API et collecte Proxmox.
- `detection.py` : regles d'alertes, score et severite.
- `actions.py` : isolement/restauration QEMU `net0`.
- `storage.py` : persistance SQLite des metriques, alertes et actions.

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
```

`PROTECTED_VMIDS` accepte une liste separee par virgules, par exemple `100,101`. Ces VM ne peuvent pas etre isolees depuis le dashboard.

## Lancement Docker

```powershell
docker compose up --build -d
```

Interface :

```text
http://localhost:8501
```

La base SQLite est montee dans `./data` via Docker Compose pour conserver les preuves apres redemarrage du conteneur.

## Fonctionnalites

- Vue globale du noeud Proxmox : CPU, RAM, SWAP.
- Inventaire des VM QEMU.
- Graphiques quasi temps reel pour l'hote et les VM.
- Moteur d'alertes configurable :
  - CPU host ;
  - CPU VM ;
  - RAM VM ;
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

## Protocole experimental

Scenario reproductible pour une demonstration de soutenance :

1. Demarrer le dashboard et verifier l'etat normal du noeud.
2. Selectionner une VM QEMU cible non protegee.
3. Generer une charge CPU controlee sur la VM cible.
4. Observer l'apparition de l'alerte dans `Supervision` puis `Incidents / Alertes`.
5. Noter le score, la severite et l'horodatage de detection.
6. Confirmer l'isolement dans `Reponse active`.
7. Verifier que `net0` passe en etat isole.
8. Restaurer le reseau.
9. Utiliser la timeline et le journal d'audit comme preuve experimentale.

Exemple Linux pour generer une charge CPU de demonstration dans une VM de test :

```bash
yes > /dev/null
```

Arreter la charge :

```bash
pkill yes
```

## Justification academique

- Pitkar (2025) soutient l'interet de l'automatisation pour coordonner detection et reponse dans des environnements cloud.
- Iacovazzi et Raza (2023) motivent l'evolution future vers des modeles de type Isolation Forest lorsque l'historique sera suffisant.
- Lee et al. (2022), SIERRA, inspire la priorisation par score/severite afin d'aider l'analyste.
- Jindal et al. (2021), IAD, soutient l'interet d'une detection indirecte a partir des metriques de ressources VM/hyperviseur.

## Limites actuelles

- Detection par seuils explicables, pas encore par apprentissage automatique.
- Polling API regulier, pas d'architecture event-driven.
- Pas de correlation avancee avec Syslog ou logs SSH.
- Pas de detection reseau profonde.
- Pas de remediations autonomes completes : l'analyste valide l'isolement.
- Lab uniquement avec `VERIFY_SSL=False`; a corriger pour une production.
