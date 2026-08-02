# TP1 — IDS/IPS maison (Scapy + fpdf2 + pygal)

Mini IDS/IPS écrit en Python. Il capture le trafic sur une interface,
liste les protocoles rencontrés, détecte deux familles d'attaques
(ARP spoofing et SQL injection), applique une politique de blocage
optionnelle via iptables et produit un rapport PDF.

## Architecture

```
src/tp1/
├── main.py                  # entrée: capture → analyse → rapport
└── utils/
    ├── config.py            # logger TP1
    ├── lib.py               # choose_interface (Scapy)
    ├── capture.py           # Capture: sniff, comptage, détecteurs, blocage
    └── report.py            # Report: PDF (fpdf2) + chart SVG (pygal)
```

## Détecteurs implémentés

**ARP Spoofing** — une même IP source déclarée par plusieurs adresses MAC
dans des paquets ARP reply (op=2). Signal d'un attaquant qui tente
de se faire passer pour la passerelle.

**SQL Injection** — pattern matching regex sur les payloads TCP en clair
(HTTP plaintext). 8 signatures couvertes :
- `' OR 1=1`
- `UNION SELECT`
- `DROP TABLE`
- `INSERT INTO`
- Commentaires SQL `/* ... */` et `-- `
- `xp_cmdshell` (SQL Server)
- `EXEC(...)`

Chaque menace détectée est stockée avec : type d'attaque, protocole, IP
source, MAC source et détails contextuels.

## Blocage (task 4c facultative)

`_block_attackers()` ajoute une règle `iptables -A INPUT -s <IP> -j DROP`
par IP unique détectée. Deux modes :

- **Dry-run** (défaut, safer) : loggue ce qui serait bloqué, ne touche
  pas au firewall
- **Réel** : bloque effectivement. Activable avec la variable d'environnement
  `TP1_BLOCK_ATTACKERS=1`

Gestion d'erreurs incluse : `CalledProcessError`, binaire absent, timeout.

## Rapport PDF

Généré avec fpdf2 (natif, pas de dépendance à cairo/imagemagick) :

- Titre
- Summary textuel (nombre de paquets, distribution des protocoles)
- Bar chart horizontal des protocoles (dessin natif fpdf2)
- Tableau protocole/count
- Section rouge "threats detected" si menaces
- Section verte "Blocking actions" listant les IPs bloquées

Un fichier `chart.svg` séparé est aussi produit via pygal.

## Lancement

Depuis la racine du projet :

```bash
poetry install
sudo /home/$USER/.cache/pypoetry/virtualenvs/template-code-*/bin/python -m tp1.main
```

`sudo` est nécessaire car Scapy `sniff()` a besoin de `CAP_NET_RAW`
sur l'interface. Le script demande l'interface au démarrage.

Pour activer le blocage réel :

```bash
sudo TP1_BLOCK_ATTACKERS=1 <chemin_venv>/bin/python -m tp1.main
```

## Tests

```bash
poetry run pytest tests/tp1/ -v
```

36 tests unitaires couvrant :
- `choose_interface` (mocks stdin + Scapy)
- `capture_traffic` (mock sniff + gestion permission)
- Comptage et tri des protocoles (paquets synthétiques)
- Détection ARP spoofing (vrais paquets Scapy)
- Détection SQL injection (vrais paquets Scapy)
- Blocage attaquant (dry-run, réel, dedup, erreurs iptables)
- Génération du rapport (magic bytes PDF vérifiés, SVG XML vérifié)

## Limites connues à mentionner en défense

- SQLi visible seulement sur HTTP plaintext (pas HTTPS sans MITM TLS)
- Détection signature-based → contournable par variations d'encoding
- ARP spoofing detection : suppose qu'on capture assez de trafic ARP
- Sous WSL2, la capture sur `lo` peut être limitée par le kernel WSL

Les vrais IDS de production (Snort, Suricata, Zeek) combinent
signatures + analyse comportementale + ML.