from flask import Flask, render_template, Blueprint, jsonify, request
from .app import app
from .analyzer import DomainAnalyzer

# Create Blueprint for domain analyzer
router = Blueprint('analyzer', __name__, 
                  template_folder='templates',
                  static_folder='static',
                  url_prefix='/analyzer')

# Main route to serve analyzer interface
@router.route('/')
def get_analyzer_page():
    return render_template('index.html')


# API route for domain analysis (synchronous simple implementation)
@router.route('/analyze/<domain>', methods=['GET'])
def analyze_domain(domain):
    """Analyze a domain and return its information synchronously.

    This endpoint performs a single-domain analysis and returns the
    result as JSON. For large/batch scans you should use the upload
    endpoint which runs analyses in background threads and emits
    progress via SocketIO.
    """
    try:
        timeout = int(request.args.get('timeout', 10))
    except Exception:
        timeout = 10

    analyzer = DomainAnalyzer(timeout=timeout)
    result = analyzer.analyze_domain(domain)
    return jsonify(result)


# Register blueprint with the app
app.register_blueprint(router)