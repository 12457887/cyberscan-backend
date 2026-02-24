#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Application Web Domain Analyzer Pro
Upload, analyse, suivi temps réel, export CSV/JSON
"""

from flask import Flask

# Create the Flask app instance at module level
app = Flask(__name__, static_folder='static')

from flask import Flask, render_template, request, jsonify, send_file, session
from flask_socketio import SocketIO, emit
from werkzeug.utils import secure_filename
import os

import json
import csv
import io
import uuid
from datetime import datetime
from threading import Thread
from .analyzer import DomainAnalyzer, generate_domain_hash
import sqlite3

app = Flask(__name__, static_folder='static')
app.config['SECRET_KEY'] = 'domain-analyzer-secret-key-2024'
app.config['UPLOAD_FOLDER'] = '/tmp/uploads'
app.config['MAX_CONTENT_LENGTH'] = 50 * 1024 * 1024  # 50MB max

socketio = SocketIO(app, cors_allowed_origins="*", async_mode='threading')

# Créer le dossier d'upload
os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)

# Base de données SQLite
DB_PATH = '/tmp/domain_analyzer.db'

def init_db():
    """Initialiser la base de données"""
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    
    # Table des analyses
    c.execute('''CREATE TABLE IF NOT EXISTS analyses
                 (id TEXT PRIMARY KEY,
                  name TEXT,
                  total_domains INTEGER,
                  completed INTEGER,
                  status TEXT,
                  created_at TEXT,
                  completed_at TEXT)''')
    
    # Table des résultats
    c.execute('''CREATE TABLE IF NOT EXISTS results
                 (id INTEGER PRIMARY KEY AUTOINCREMENT,
                  analysis_id TEXT,
                  domain TEXT,
                  domain_hash TEXT UNIQUE,
                  online INTEGER,
                  ip TEXT,
                  url TEXT,
                  title TEXT,
                  keywords TEXT,
                  cms TEXT,
                  technologies TEXT,
                  emails TEXT,
                  phones TEXT,
                  status_code INTEGER,
                  error TEXT,
                  created_at TEXT,
                  FOREIGN KEY (analysis_id) REFERENCES analyses(id))''')
    
    c.execute('CREATE INDEX IF NOT EXISTS idx_analysis_id ON results(analysis_id)')
    c.execute('CREATE INDEX IF NOT EXISTS idx_domain_hash ON results(domain_hash)')
    
    conn.commit()
    conn.close()

init_db()

# Stockage des analyses en cours
active_analyses = {}

def save_analysis(analysis_id, name, total_domains):
    """Sauvegarder une nouvelle analyse"""
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute('''INSERT INTO analyses VALUES (?, ?, ?, ?, ?, ?, ?)''',
              (analysis_id, name, total_domains, 0, 'running',
               datetime.now().isoformat(), None))
    conn.commit()
    conn.close()

def update_analysis_progress(analysis_id, completed):
    """Mettre à jour la progression"""
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute('UPDATE analyses SET completed = ? WHERE id = ?',
              (completed, analysis_id))
    conn.commit()
    conn.close()

def complete_analysis(analysis_id):
    """Marquer l'analyse comme terminée"""
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute('''UPDATE analyses SET status = ?, completed_at = ? WHERE id = ?''',
              ('completed', datetime.now().isoformat(), analysis_id))
    conn.commit()
    conn.close()

def save_result(analysis_id, result):
    """Sauvegarder un résultat (évite les duplications)"""
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    
    domain_hash = generate_domain_hash(result['domain'])
    
    try:
        c.execute('''INSERT INTO results
                     (analysis_id, domain, domain_hash, online, ip, url, title,
                      keywords, cms, technologies, emails, phones,
                      status_code, error, created_at)
                     VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)''',
                  (analysis_id, result['domain'], domain_hash,
                   1 if result['online'] else 0,
                   result['ip'], result['url'], result['title'],
                   json.dumps(result['keywords']),
                   json.dumps(result['cms']),
                   json.dumps(result['technologies']),
                   json.dumps(result['emails']),
                   json.dumps(result['phones']),
                   result['status_code'], result['error'],
                   datetime.now().isoformat()))
        conn.commit()
        return True
    except sqlite3.IntegrityError:
        # Domaine déjà analysé
        return False
    finally:
        conn.close()

def get_analysis(analysis_id):
    """Récupérer une analyse"""
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute('SELECT * FROM analyses WHERE id = ?', (analysis_id,))
    row = c.fetchone()
    conn.close()
    
    if row:
        return {
            'id': row[0],
            'name': row[1],
            'total_domains': row[2],
            'completed': row[3],
            'status': row[4],
            'created_at': row[5],
            'completed_at': row[6]
        }
    return None

def get_all_analyses():
    """Récupérer toutes les analyses"""
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute('SELECT * FROM analyses ORDER BY created_at DESC')
    rows = c.fetchall()
    conn.close()
    
    analyses = []
    for row in rows:
        analyses.append({
            'id': row[0],
            'name': row[1],
            'total_domains': row[2],
            'completed': row[3],
            'status': row[4],
            'created_at': row[5],
            'completed_at': row[6]
        })
    return analyses

def get_results(analysis_id, filters=None):
    """Récupérer les résultats d'une analyse"""
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    
    query = 'SELECT * FROM results WHERE analysis_id = ?'
    params = [analysis_id]
    
    if filters:
        if filters.get('online_only'):
            query += ' AND online = 1'
        if filters.get('cms'):
            query += ' AND cms LIKE ?'
            params.append(f'%{filters["cms"]}%')
        if filters.get('has_email'):
            query += ' AND emails != "[]"'
        if filters.get('has_phone'):
            query += ' AND phones != "[]"'
    
    c.execute(query, params)
    rows = c.fetchall()
    conn.close()
    
    results = []
    for row in rows:
        results.append({
            'id': row[0],
            'analysis_id': row[1],
            'domain': row[2],
            'online': bool(row[4]),
            'ip': row[5],
            'url': row[6],
            'title': row[7],
            'keywords': json.loads(row[8]) if row[8] else [],
            'cms': json.loads(row[9]) if row[9] else [],
            'technologies': json.loads(row[10]) if row[10] else [],
            'emails': json.loads(row[11]) if row[11] else [],
            'phones': json.loads(row[12]) if row[12] else [],
            'status_code': row[13],
            'error': row[14],
            'created_at': row[15]
        })
    return results

def analyze_domains_task(analysis_id, domains):
    """Tâche d'analyse en arrière-plan"""
    analyzer = DomainAnalyzer(timeout=10)
    
    def progress_callback(completed, total, result):
        # Sauvegarder le résultat
        if result:
            save_result(analysis_id, result)
        
        # Mettre à jour la progression
        update_analysis_progress(analysis_id, completed)
        
        # Émettre la progression via WebSocket
        socketio.emit('progress', {
            'analysis_id': analysis_id,
            'completed': completed,
            'total': total,
            'percentage': round((completed / total) * 100, 2),
            'result': result
        })
    
    # Lancer l'analyse
    analyzer.analyze_domains_batch(domains, max_workers=20, progress_callback=progress_callback)
    
    # Marquer comme terminé
    complete_analysis(analysis_id)
    socketio.emit('completed', {'analysis_id': analysis_id})

@app.route('/')
def index():
    """Page d'accueil"""
    return render_template('index.html')

@app.route('/api/analyses', methods=['GET'])
def list_analyses():
    """Lister toutes les analyses"""
    analyses = get_all_analyses()
    return jsonify(analyses)

@app.route('/api/upload', methods=['POST'])
def upload_file():
    """Upload et démarrer l'analyse"""
    if 'file' not in request.files:
        return jsonify({'error': 'No file provided'}), 400
    
    file = request.files['file']
    if file.filename == '':
        return jsonify({'error': 'No file selected'}), 400
    
    # Lire les domaines
    content = file.read().decode('utf-8')
    domains = [line.strip() for line in content.split('\n') if line.strip()]
    
    # Dédupliquer
    domains = list(dict.fromkeys(domains))
    
    if not domains:
        return jsonify({'error': 'No valid domains found'}), 400
    
    # Créer une nouvelle analyse
    analysis_id = str(uuid.uuid4())
    analysis_name = request.form.get('name', file.filename)
    
    save_analysis(analysis_id, analysis_name, len(domains))
    
    # Lancer l'analyse en arrière-plan
    thread = Thread(target=analyze_domains_task, args=(analysis_id, domains))
    thread.daemon = True
    thread.start()
    
    return jsonify({
        'analysis_id': analysis_id,
        'total_domains': len(domains),
        'message': 'Analysis started'
    })

@app.route('/api/analysis/<analysis_id>', methods=['GET'])
def get_analysis_status(analysis_id):
    """Obtenir le statut d'une analyse"""
    analysis = get_analysis(analysis_id)
    if not analysis:
        return jsonify({'error': 'Analysis not found'}), 404
    return jsonify(analysis)

@app.route('/api/results/<analysis_id>', methods=['GET'])
def get_analysis_results(analysis_id):
    """Obtenir les résultats d'une analyse"""
    filters = {
        'online_only': request.args.get('online_only') == 'true',
        'cms': request.args.get('cms'),
        'has_email': request.args.get('has_email') == 'true',
        'has_phone': request.args.get('has_phone') == 'true'
    }
    
    results = get_results(analysis_id, filters)
    return jsonify(results)

@app.route('/api/export/<analysis_id>/<format>', methods=['GET'])
def export_results(analysis_id, format):
    """Exporter les résultats en CSV ou JSON"""
    filters = {
        'online_only': request.args.get('online_only') == 'true',
        'cms': request.args.get('cms'),
        'has_email': request.args.get('has_email') == 'true',
        'has_phone': request.args.get('has_phone') == 'true'
    }
    
    results = get_results(analysis_id, filters)
    analysis = get_analysis(analysis_id)
    
    if format == 'json':
        output = io.BytesIO()
        output.write(json.dumps(results, indent=2, ensure_ascii=False).encode('utf-8'))
        output.seek(0)
        return send_file(
            output,
            mimetype='application/json',
            as_attachment=True,
            download_name=f'{analysis["name"]}_results.json'
        )
    
    elif format == 'csv':
        output = io.StringIO()
        if results:
            fieldnames = ['domain', 'online', 'ip', 'url', 'title', 'keywords',
                         'cms', 'technologies', 'emails', 'phones', 'status_code', 'error']
            writer = csv.DictWriter(output, fieldnames=fieldnames)
            writer.writeheader()
            
            for result in results:
                writer.writerow({
                    'domain': result['domain'],
                    'online': 'Yes' if result['online'] else 'No',
                    'ip': result['ip'] or '',
                    'url': result['url'] or '',
                    'title': result['title'] or '',
                    'keywords': '; '.join(result['keywords']),
                    'cms': '; '.join(result['cms']),
                    'technologies': '; '.join(result['technologies']),
                    'emails': '; '.join(result['emails']),
                    'phones': '; '.join(result['phones']),
                    'status_code': result['status_code'] or '',
                    'error': result['error'] or ''
                })
        
        output.seek(0)
        return send_file(
            io.BytesIO(output.getvalue().encode('utf-8')),
            mimetype='text/csv',
            as_attachment=True,
            download_name=f'{analysis["name"]}_results.csv'
        )
    
    return jsonify({'error': 'Invalid format'}), 400

if __name__ == '__main__':
    socketio.run(app, host='0.0.0.0', port=5000, debug=True)

