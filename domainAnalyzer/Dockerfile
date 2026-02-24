FROM python:3.11-slim

# Installer les dépendances système
RUN apt-get update && apt-get install -y \
    gcc \
    && rm -rf /var/lib/apt/lists/*

# Créer le répertoire de travail
WORKDIR /app

# Copier les fichiers de dépendances
COPY requirements.txt .

# Installer les dépendances Python
RUN pip install --no-cache-dir -r requirements.txt
RUN pip install --no-cache-dir gunicorn

# Copier le code de l'application
COPY . .

# Créer les dossiers nécessaires
RUN mkdir -p /tmp/uploads

# Exposer le port
EXPOSE 5000

# Variables d'environnement
ENV PYTHONUNBUFFERED=1
ENV PORT=5000

# Lancer l'application avec Gunicorn
CMD ["gunicorn", "--worker-class", "eventlet", "-w", "1", "--bind", "0.0.0.0:5000", "--timeout", "120", "app:app"]

