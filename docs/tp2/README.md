# TP2 — Analyse de shellcodes Windows (multi-outils + LLM)

Analyseur de shellcodes Windows x86 32-bit combinant quatre techniques
complémentaires : extraction de chaînes, désassemblage statique,
émulation dynamique, et synthèse par LLM local.

## Architecture

```
src/tp2/
├── main.py                  # entrée: argparse + pipeline
└── utils/
    ├── config.py            # logger TP2
    ├── lib.py               # parse_shellcode / load_shellcode (\xHH format)
    ├── api_hashes.py        # table ROR13 → nom d'API Windows
    └── analyzer.py          # 4 analyseurs + LLM
```

## Les 4 analyseurs

### 1. `get_shellcode_strings`
Extraction de chaînes en trois passes :
- **ASCII brut** : scan des runs de bytes imprimables `[0x20-0x7e]`
- **UTF-16LE** : détection des paires `printable+null` (wide strings Windows)
- **Stack-pushed** *(bonus)* : reconstruction des chaînes assemblées sur
  la pile via des séries de `push imm32` (technique Metasploit classique).
  C'est la méthode la plus efficace sur les shellcodes réels — elle
  reconstitue correctement `cmd.exe /c net user BroK3n BroK3n /ADD` là
  où un scan ASCII naïf ne voit qu'un fatras fragmenté.

### 2. `get_capstone_analysis`
Désassemblage x86 32-bit via Capstone (moteur utilisé par IDA, Ghidra,
radare2). Retourne une liste structurée d'instructions avec address,
mnemonic, op_str et bytes. Base address configurable pour affichage
d'adresses virtuelles réalistes.

### 3. `get_pylibemu_analysis`
Émulation dynamique du shellcode.

**Choix technique** : la fonction porte le nom `get_pylibemu_analysis`
pour respecter le contrat de l'interface TP, mais utilise en interne
**Unicorn Engine** (backend QEMU, activement maintenu 2025) au lieu
de pylibemu (wrapper de libemu, non maintenu depuis 2011, sans
paquet `libemu-dev` dans Ubuntu 22.04+). Le résultat pour l'analyste
est équivalent : identification des API Windows résolues.

Stratégie : hook sur chaque instruction, surveillance de EBX pour
détecter les hashes ROR13 utilisés par le pattern Metasploit de
résolution d'API. Table pré-calculée de hashes couvrant kernel32,
urlmon, ws2_32.

**Limite** : l'émulation est best-effort. Les shellcodes s'attendent
à un vrai environnement Windows avec PEB valide (adresse `fs:[0x30]`).
En son absence, ils bouclent dans du code invalide. Le mécanisme de
détection ROR13 est validé unit-testable via un stub artisanal ; sur
les shellcodes réels le safety cap de 5000 instructions se déclenche
avant que les hashes ne soient testés.

### 4. `get_llm_analysis`
Synthèse par LLM local via Ollama.

- Backend : Ollama HTTP API (par défaut `qwen2.5:7b`, configurable
  via `TP2_LLM_MODEL` et `TP2_LLM_URL`)
- Prompt system en français, persona d'analyste malware
- Prompt aggrège les 3 catégories de strings + désassemblage (40
  premières instructions) + APIs détectées
- Section "Stack-pushed" mise en avant comme indicateur principal
- Temperature basse (0.2) pour output factuel
- Gestion d'erreurs : ConnectionError, Timeout, HTTP error, JSON invalide
- Flag `--skip-llm` pour bypasser quand Ollama est indisponible

## Résultats sur les 3 shellcodes du cours

| Shellcode | Taille | Verdict LLM | Correct ? |
|---|---|---|---|
| easy | 202 B | Downloader utilisant urlmon.dll et C:\U.exe | ✅ |
| medium | 194 B | Création de compte administrateur "BroK3n" via `net user /ADD` | ✅ |
| hard | 354 B | Communication réseau (ws2_32) — reverse shell TCP | ✅ |

## Lancement

```bash
poetry install
poetry run tp2 -f shellcodes/easy.txt
poetry run tp2 -f shellcodes/medium.txt
poetry run tp2 -f shellcodes/hard.txt
```

Pour bypasser le LLM (Ollama indisponible) :
```bash
poetry run tp2 -f shellcodes/easy.txt --skip-llm
```

Pour utiliser un autre modèle Ollama :
```bash
TP2_LLM_MODEL=llama3.2:3b poetry run tp2 -f shellcodes/easy.txt
```

## Tests

```bash
poetry run pytest tests/tp2/ -v
```

37 tests unitaires couvrant :
- Parsing hex `\xHH` (5 tests : basic, casse, whitespace, empty, file)
- Extraction ASCII/UTF-16LE (7 tests)
- Extraction stack-pushed (6 tests dont sanity checks sur medium/hard)
- Désassemblage capstone (5 tests dont NOP/XOR/RET, empty, real shellcode)
- Émulation unicorn (4 tests dont détection ROR13 sur stub artisanal)
- LLM analysis (7 tests : composition du prompt + toutes les error paths)

## Dépendances ajoutées

- `capstone` : désassembleur x86
- `unicorn` : moteur d'émulation CPU (remplace pylibemu)
- `requests` : appels HTTP vers Ollama (déjà présent depuis TP1)
- Ollama : à installer séparément (`curl -fsSL https://ollama.com/install.sh | sh`)
- Modèle LLM : `ollama pull qwen2.5:7b` (4.7 GB)