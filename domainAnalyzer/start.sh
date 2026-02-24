#!/bin/bash

echo "🚀 Démarrage de Domain Analyzer Pro"
echo "===================================="
echo ""

# Créer les dossiers nécessaires
mkdir -p /tmp/uploads

# Vérifier les dépendances
echo "📦 Vérification des dépendances..."
python3 -c "import flask, flask_socketio, requests, bs4" 2>/dev/null
if [ $? -ne 0 ]; then
    echo "⚠️  Installation des dépendances..."
    pip3 install --user -r requirements.txt
fi

echo ""
echo "✅ Prêt !"
echo ""
echo "🌐 L'application sera accessible sur:"
echo "   http://localhost:5000"
echo ""
echo "📝 Pour arrêter: Ctrl+C"
echo ""

# Lancer l'application
python3 app.py

