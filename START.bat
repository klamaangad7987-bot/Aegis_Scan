@echo off
title Aegis Scan - DevSecOps Platform
echo.
echo ==========================================
echo   AEGIS SCAN - Demarrage automatique
echo ==========================================
echo.

:: Verifier si le venv existe
if not exist "venv\Scripts\python.exe" (
    echo [SETUP] Creation de l'environnement virtuel...
    python -m venv venv
    echo [SETUP] Installation des dependances ^(patience ~5 min^)...
    venv\Scripts\pip install --upgrade pip --quiet
    venv\Scripts\pip install -r requirements.txt
    echo [SETUP] Installation terminee !
    echo.
)

:: Supprimer ancienne DB si corrompue
if exist "devsecops.db" (
    echo [INFO] Base de donnees existante conservee.
) else (
    echo [INFO] Nouvelle base de donnees sera creee au demarrage.
)

echo [START] Lancement de l'application...
echo.
echo   URL : http://127.0.0.1:5000
echo.
echo Appuyez sur Ctrl+C pour arreter
echo.
venv\Scripts\python run.py
pause
