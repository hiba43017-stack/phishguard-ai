"""
PhishGuard AI - Flask Application Entry Point
Run this file to start the development server.
"""
import os
from dotenv import load_dotenv

# Load environment variables from .env file
load_dotenv()

from app import create_app

app = create_app()

if __name__ == '__main__':
    print("=" * 60)
    print("  PhishGuard AI - Phishing Email Detection System")
    print("=" * 60)
    print("  Starting server at: http://127.0.0.1:5000")
    print("  Press CTRL+C to stop the server")
    print("=" * 60)
    app.run(
        host='127.0.0.1',
        port=5000,
        debug=os.getenv('FLASK_DEBUG', 'True').lower() == 'true'
    )
