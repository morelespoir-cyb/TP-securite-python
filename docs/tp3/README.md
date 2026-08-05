# TP3 — Captcha solver

Client automatisé pour résoudre des CAPTCHAs textuels et récupérer un
flag. Utilise Tesseract OCR pour la reconnaissance de caractères et
BeautifulSoup pour parser les pages du serveur de challenge.

## Architecture

```
src/tp3/
├── main.py                    # argparse + boucle de résolution
└── utils/
    ├── config.py              # logger TP3
    ├── captcha.py             # Captcha: capture image + OCR
    └── session.py             # Session: prepare + submit + parse response

tests/tp3/utils/
├── captcha_fixtures.py        # génère des CAPTCHAs locaux via Pillow
├── test_captcha.py            # 12 tests avec mocks HTTP + fixtures
└── test_session.py            # 10 tests avec response bodies mockés
```

## Cycle de résolution

```
┌─────────────────┐
│ Session(url)    │
└────────┬────────┘
         │
    ┌────┴─────────────────────┐
    │ prepare_request()        │
    │  ├─ Captcha(url)         │
    │  ├─ captcha.capture()    │  ← GET challenge, parse HTML,
    │  │                       │    extract token + image URL,
    │  │                       │    download image
    │  └─ captcha.solve()      │  ← grayscale + threshold + OCR
    ├──────────────────────────┤
    │ submit_request()         │  ← POST captcha + token
    ├──────────────────────────┤
    │ process_response()       │  ← True: flag captured
    │                          │    False: retry
    └──────────────────────────┘
```

## Détails techniques

### `Captcha.capture()`
- `requests.Session` pour préserver les cookies entre GET et POST
- Parsing HTML avec BeautifulSoup (`html.parser`, pas de dépendance lxml)
- Extraction du token CSRF/session via 4 noms candidats communs
  (`token`, `csrf`, `csrf_token`, `session_id`)
- Résolution des URLs d'image relatives contre l'URL de base
- Timeout de 15s (raisonnable pour un serveur de TP)

### `Captcha.solve()`
- Preprocessing : conversion en niveaux de gris puis seuillage binaire à 128
  (augmente le contraste des glyphes, réduit le bruit)
- Tesseract en mode `--psm 8` (single word) — optimal pour les CAPTCHAs
  courts sans structure de ligne
- Whitelist de caractères configurable (par défaut `A-Z0-9`) via l'option
  Tesseract `tessedit_char_whitelist`
- Post-filtrage Python pour ne garder que les caractères autorisés
- Défensif : lève `RuntimeError` si `solve()` est appelé avant `capture()`

### `Session.process_response()`
Trois stratégies d'extraction du flag, dans l'ordre :
1. **Regex patterns** — cherche `flag: XXX`, `congratulations ... XXX`,
   ou un hexstring long (>= 16 chars)
2. **Sélecteurs CSS** — cherche un `#flag`, `.flag`, `<code>` ou `<pre>`
   dans le HTML de la réponse
3. **Mot-clé d'échec** — détecte `wrong`, `incorrect`, `invalid`,
   `try again`, `failed` pour signaler un retry

## Contournement du serveur du prof

Le serveur du prof (`31.220.95.27:9002`) était injoignable au moment du
développement (l'IP répond au ping, mais le port 9002 refuse la connexion).

Pour permettre les tests offline :
- **`captcha_fixtures.py`** génère des images CAPTCHA locales avec Pillow
  (fonts DejaVu ou Liberation), avec un niveau de bruit configurable
- **Tous les tests** mockent `requests.Session.get/post` — aucun appel
  réseau réel n'est fait
- Le code fonctionnera tel quel dès que le serveur du prof sera relancé

## Lancement

```bash
poetry install
poetry run tp3
```

Avec options :
```bash
# Tenter 5 challenges au lieu de 2
poetry run tp3 --challenges 1 2 3 4 5

# Augmenter la limite de retries (défaut 30)
poetry run tp3 --max-attempts 100

# Changer de serveur
poetry run tp3 --server 10.0.0.1:8080
```

## Tests

```bash
poetry run pytest tests/tp3/ -v
```

22 tests unitaires couvrant :
- Initialisation (Captcha, Session)
- Capture : URL absolue, URL relative, extraction de token, page sans image
- OCR : captcha propre, numérique, alphanumérique bruité, whitelist,
  garde `capture()` requis
- Session : orchestration prepare→submit, envoi du token, retry sur échec,
  extraction du flag via regex/CSS/hex

## Dépendances ajoutées

- `pytesseract` (0.3.13) : wrapper Python de Tesseract OCR
- `Pillow` (12.3.0) : traitement d'images
- `beautifulsoup4` (4.15.0) : parsing HTML
- `tesseract-ocr` (binaire système) : moteur OCR de Google
- `tesseract-ocr-eng` : données pour la langue anglaise (par défaut)