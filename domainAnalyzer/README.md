# Domain Analyzer Pro

Application web complète pour analyser des milliers de domaines .fr en temps réel.

## 🎯 Fonctionnalités

- ✅ **Upload de listes** - Importez des milliers de domaines via fichier .txt
- 🔍 **Analyse complète** - CMS, technologies, emails, téléphones, titre, mots-clés, IP
- 📊 **Suivi en temps réel** - Progression live avec WebSocket
- 🚫 **Anti-duplication** - Évite d'analyser deux fois le même domaine
- 🔎 **Filtres avancés** - Par statut, CMS, présence d'email/téléphone
- 📥 **Export** - CSV et JSON avec filtres appliqués
- 💾 **Historique** - Conserve toutes les analyses précédentes
- ⚡ **Performance** - Traitement parallèle de 20 domaines simultanément

## 📦 Installation

### Prérequis

- Python 3.8+
- pip

### Installation des dépendances

```bash
cd domain-analyzer-pro
pip install -r requirements.txt
```

## 🚀 Lancement

### Mode développement

```bash
python app.py
```

L'application sera accessible sur `http://localhost:5000`

### Mode production

#### Avec Gunicorn

```bash
pip install gunicorn
gunicorn --worker-class eventlet -w 1 --bind 0.0.0.0:5000 app:app
```

#### Avec Docker

```bash
# Construire l'image
docker build -t domain-analyzer-pro .

# Lancer le conteneur
docker run -d -p 5000:5000 domain-analyzer-pro
```

## 📋 Utilisation

1. **Préparer votre fichier**
   - Créez un fichier `.txt` avec un domaine par ligne
   - Exemple:
     ```
     google.fr
     lemonde.fr
     ovh.com
     ```

2. **Uploader le fichier**
   - Glissez-déposez ou cliquez pour sélectionner
   - Donnez un nom à votre analyse (optionnel)
   - Cliquez sur "Démarrer l'analyse"

3. **Suivre la progression**
   - Progression en temps réel avec barre de progression
   - Statistiques live (total, complété, en ligne, hors ligne)
   - Résultats affichés au fur et à mesure

4. **Filtrer et exporter**
   - Filtrez par: Tous, En ligne, Avec email, Avec téléphone
   - Exportez en CSV ou JSON
   - Les filtres sont appliqués à l'export

## 🗄️ Structure de la base de données

### Table `analyses`
- `id` - Identifiant unique de l'analyse
- `name` - Nom de l'analyse
- `total_domains` - Nombre total de domaines
- `completed` - Nombre de domaines analysés
- `status` - Statut (running/completed)
- `created_at` - Date de création
- `completed_at` - Date de fin

### Table `results`
- `id` - Identifiant unique
- `analysis_id` - Référence à l'analyse
- `domain` - Nom de domaine
- `domain_hash` - Hash MD5 (pour éviter duplications)
- `online` - Statut en ligne (0/1)
- `ip` - Adresse IP
- `url` - URL finale
- `title` - Titre de la page
- `keywords` - Mots-clés (JSON array)
- `cms` - CMS détecté (JSON array)
- `technologies` - Technologies (JSON array)
- `emails` - Emails trouvés (JSON array)
- `phones` - Téléphones (JSON array)
- `status_code` - Code HTTP
- `error` - Message d'erreur
- `created_at` - Date d'analyse

## 🔧 Configuration

### Variables d'environnement

```bash
# Port de l'application
export PORT=5000

# Chemin de la base de données
export DB_PATH=/path/to/database.db

# Dossier d'upload
export UPLOAD_FOLDER=/path/to/uploads

# Nombre de workers parallèles
export MAX_WORKERS=20

# Timeout par domaine (secondes)
export DOMAIN_TIMEOUT=10
```

### Personnalisation

Éditez `app.py` pour modifier:
- `MAX_WORKERS` - Nombre de domaines analysés en parallèle (ligne 20 dans analyzer.py)
- `DOMAIN_TIMEOUT` - Timeout par domaine (ligne 10 dans analyzer.py)
- `MAX_CONTENT_LENGTH` - Taille max du fichier uploadé (ligne 17 dans app.py)

## 📊 Format des exports

### CSV
```csv
domain,online,ip,url,title,keywords,cms,technologies,emails,phones,status_code,error
google.fr,Yes,173.194.195.94,https://google.fr,Google,search; engine,Unknown,Angular; Server: gws,,,200,
```

### JSON
```json
[
  {
    "domain": "google.fr",
    "online": true,
    "ip": "173.194.195.94",
    "url": "https://google.fr",
    "title": "Google",
    "keywords": ["search", "engine"],
    "cms": ["Unknown"],
    "technologies": ["Angular", "Server: gws"],
    "emails": [],
    "phones": [],
    "status_code": 200,
    "error": null
  }
]
```

## 🐳 Déploiement Docker

### Dockerfile

```dockerfile
FROM python:3.11-slim

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

EXPOSE 5000

CMD ["gunicorn", "--worker-class", "eventlet", "-w", "1", "--bind", "0.0.0.0:5000", "app:app"]
```

### docker-compose.yml

```yaml
version: '3.8'

services:
  domain-analyzer:
    build: .
    ports:
      - "5000:5000"
    volumes:
      - ./data:/tmp
    environment:
      - PORT=5000
    restart: unless-stopped
```

## 🌐 Déploiement sur serveur

### Nginx (reverse proxy)

```nginx
server {
    listen 80;
    server_name votre-domaine.com;

    location / {
        proxy_pass http://127.0.0.1:5000;
        proxy_http_version 1.1;
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection "upgrade";
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
    }
}
```

### Systemd service

```ini
[Unit]
Description=Domain Analyzer Pro
After=network.target

[Service]
Type=simple
User=www-data
WorkingDirectory=/path/to/domain-analyzer-pro
ExecStart=/usr/bin/gunicorn --worker-class eventlet -w 1 --bind 127.0.0.1:5000 app:app
Restart=always

[Install]
WantedBy=multi-user.target
```

## 🔒 Sécurité

- Changez la `SECRET_KEY` dans `app.py`
- Limitez la taille des fichiers uploadés
- Utilisez HTTPS en production
- Ajoutez une authentification si nécessaire
- Limitez le nombre de requêtes par IP

## 📈 Performance

- **Vitesse** : ~200-300 domaines/minute
- **Parallélisme** : 20 workers par défaut
- **Mémoire** : ~500MB pour 10 000 domaines
- **Base de données** : SQLite (peut être migré vers PostgreSQL)

## 🐛 Dépannage

### L'analyse ne démarre pas
- Vérifiez que le fichier contient des domaines valides
- Vérifiez les logs de l'application

### Résultats incomplets
- Augmentez le timeout dans `analyzer.py`
- Vérifiez votre connexion internet

### Erreur de base de données
- Vérifiez les permissions sur `/tmp`
- Supprimez `/tmp/domain_analyzer.db` pour réinitialiser

## 📝 Licence

MIT License - Libre d'utilisation

## 🤝 Support

Pour toute question ou problème, consultez le code source ou créez une issue.

