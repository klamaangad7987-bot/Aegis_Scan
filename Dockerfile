FROM python:3.12-slim

LABEL maintainer="DevSecOps PFE"
LABEL description="SecureAudit — Plateforme DevSecOps"

# Variables d'environnement
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    FLASK_ENV=production \
    APP_HOME=/app

# Créer un utilisateur non-root (bonne pratique sécurité)
RUN groupadd -r appuser && useradd -r -g appuser appuser

WORKDIR $APP_HOME

# Installer les dépendances système
RUN apt-get update && apt-get install -y --no-install-recommends \
    gcc \
    curl \
    && rm -rf /var/lib/apt/lists/*

# Installer les dépendances Python
COPY requirements.txt .
RUN pip install --no-cache-dir --upgrade pip && \
    pip install --no-cache-dir -r requirements.txt

# Copier le code source
COPY . .

# Créer les dossiers nécessaires
RUN mkdir -p uploads reports_output && \
    chown -R appuser:appuser $APP_HOME

# Passer à l'utilisateur non-root
USER appuser

# Exposer le port
EXPOSE 5000

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
    CMD curl -f http://localhost:5000/ || exit 1

# Commande de démarrage
CMD ["gunicorn", "--bind", "0.0.0.0:5000", "--workers", "4", "--timeout", "120", "run:app"]
