# 🛡️ Aegis Scan — DevSecOps Platform (PFE)

## ⚡ Démarrage rapide

### Option 1 — Double-clic (le plus simple)
```
Double-cliquer sur START.bat
```
Le script installe tout automatiquement et lance l'app.

---

### Option 2 — VSCode Terminal

**Première fois uniquement :**
```powershell
python -m venv venv
.\venv\Scripts\Activate.ps1
pip install -r requirements.txt
```

**Ensuite (à chaque fois) :**
```powershell
.\venv\Scripts\Activate.ps1
python run.py
```

**Ou appuyer sur F5** dans VSCode (config launch.json incluse).

---

## 🌐 Accès
- URL : **http://127.0.0.1:5000**
- Créer le premier admin : voir section « Premier administrateur » ci-dessous

## 📁 Structure
```
aegis-scan/
├── run.py              # Point d'entrée
├── config.py           # Configuration
├── requirements.txt    # Dépendances (allégé)
├── START.bat           # Lanceur Windows (double-clic)
├── .env                # Variables d'environnement
├── app/
│   ├── __init__.py     # Factory Flask
│   ├── models/         # User, Scan, Vulnerability, Report
│   ├── routes/         # auth, dashboard, scan, reports, assistant
│   ├── services/       # Scanner, AI Classifier, Report Generator
│   ├── templates/      # HTML Jinja2
│   └── static/         # CSS, JS
└── .vscode/            # Config VSCode (F5 pour lancer)
```

## 🔑 Premier administrateur
Aucun compte par défaut n'est fourni. Au choix :

```bash
# Option 1 : commande interactive (recommandé)
flask create-admin

# Option 2 : variables dans .env avant le 1er lancement (mot de passe >= 12 car.)
ADMIN_USERNAME=...
ADMIN_PASSWORD=...
```
Les inscriptions publiques créent uniquement des comptes `analyst`.

## ⚙️ Fonctionnalités
- ✅ Authentification (login/register/profil)
- ✅ Dashboard avec statistiques temps réel
- ✅ Scans SAST, DAST, Docker, Dependency
- ✅ Résultats avec scoring IA des vulnérabilités
- ✅ Génération de rapports PDF
- ✅ Assistant vocal intégré
- ✅ Base de données SQLite (aucune config externe requise)

## ❗ En cas de problème

**Erreur `ModuleNotFoundError: flask`** — le venv n'est pas activé :
```powershell
.\venv\Scripts\Activate.ps1
python run.py
```

**Erreur de politique PowerShell :**
```powershell
Set-ExecutionPolicy -ExecutionPolicy RemoteSigned -Scope CurrentUser
```

**Réinstallation complète :**
```powershell
Remove-Item -Recurse -Force venv
Remove-Item -Force devsecops.db -ErrorAction SilentlyContinue
python -m venv venv
.\venv\Scripts\Activate.ps1
pip install -r requirements.txt
python run.py
```
