"""
PhishGuard AI - Flask Application Factory
This file initializes the Flask app and registers all components.
"""
import os
from flask import Flask
from .database import init_db


def create_app(test_config=None):
    """
    Application factory pattern.
    Creates and configures the Flask application instance.
    """
    app = Flask(
        __name__,
        template_folder='../templates',
        static_folder='../static'
    )

    # --- Configuration ---
    app.secret_key = os.getenv('FLASK_SECRET_KEY', 'dev-secret-key-change-in-production')
    app.config['DATABASE_PATH'] = os.getenv('DATABASE_PATH', 'instance/phishing.db')
    app.config['OLLAMA_BASE_URL'] = os.getenv('OLLAMA_BASE_URL', 'http://localhost:11434')
    app.config['OLLAMA_MODEL'] = os.getenv('OLLAMA_MODEL', 'llama3.2:3b')
    app.config['OLLAMA_TIMEOUT'] = int(os.getenv('OLLAMA_TIMEOUT', '30'))

    if test_config:
        app.config.update(test_config)
        if 'SECRET_KEY' in test_config:
            app.secret_key = test_config['SECRET_KEY']

    # --- Initialize Database ---
    # Ensure database directory exists
    db_dir = os.path.dirname(app.config['DATABASE_PATH'])
    if db_dir:
        os.makedirs(db_dir, exist_ok=True)
    init_db(app.config['DATABASE_PATH'])

    # --- Register Routes ---
    from .routes import main_bp
    app.register_blueprint(main_bp)

    return app
