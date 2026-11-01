# PhishGuard AI 🛡️

**AI-Powered Phishing Email Detection System**

A complete, full-stack cybersecurity web application that uses rule-based heuristics
combined with a locally-running Large Language Model (Llama 3.2 via Ollama) to detect
phishing emails. Built as a BCA final year project.

---

## 📸 Screenshots

> _Add screenshots here after running the application._
>
> Suggested screenshots:
> - Dashboard overview
> - Email analysis form
> - Results page with risk gauge
> - Scan history table

---

## ✨ Features

| Feature | Description |
|---------|-------------|
| 🔍 Email Analysis | Analyze emails with sender, subject, and body |
| 🤖 AI Detection | Llama 3.2 via Ollama for AI-powered analysis |
| ⚙️ Rule Engine | 15+ rule-based phishing indicators |
| 📊 Risk Scoring | 0–100 score with LOW/MEDIUM/HIGH/CRITICAL levels |
| 💾 History | SQLite-backed scan history with search and filter |
| 📄 Reports | Download scan reports as TXT or JSON |
| 📈 Dashboard | Live statistics and risk distribution chart |
| 🔒 Privacy | All processing is local — no cloud, no external APIs |

---

## 🛠️ Technology Stack

- **Language:** Python 3.11+
- **Backend:** Flask 3.0.3
- **AI:** Ollama + Llama 3.2 (llama3.2:3b)
- **Database:** SQLite (no setup required)
- **Frontend:** HTML5 / CSS3 / Vanilla JavaScript
- **Charts:** Chart.js 4
- **Testing:** Pytest + unittest.mock
- **Fonts:** Google Fonts (Inter)

---

## 📋 Prerequisites

1. **Python 3.11 or higher**
   - Download from [python.org](https://www.python.org/downloads/)
   - During install, check ✅ "Add Python to PATH"

2. **Ollama** (for AI analysis)
   - Download from [ollama.com](https://ollama.com)
   - AI analysis is optional — rule-based analysis works without Ollama

3. **Git** (for version control)
   - Download from [git-scm.com](https://git-scm.com/)

---

## 🚀 Installation & Setup

### Step 1 — Clone the Repository

```bash
git clone https://github.com/YOUR-USERNAME/phishguard-ai.git
cd phishguard-ai
```

Or if you downloaded the ZIP:

```bash
cd "phishing project"
```

### Step 2 — Create a Virtual Environment

```bash
# Windows (Command Prompt or PowerShell)
python -m venv venv
venv\Scripts\activate

# macOS / Linux
python3 -m venv venv
source venv/bin/activate
```

You should see `(venv)` at the beginning of your terminal prompt.

### Step 3 — Install Dependencies

```bash
pip install -r requirements.txt
```

### Step 4 — Configure Environment Variables

```bash
# Copy the example .env file
copy .env.example .env     # Windows
# cp .env.example .env     # macOS/Linux
```

Edit `.env` and change at minimum:
```
FLASK_SECRET_KEY=your-random-secret-key-here
```

### Step 5 — Run the Application

```bash
python run.py
```

Open your browser and visit: **http://127.0.0.1:5000**

The database (`instance/phishing.db`) is created automatically on first run.

---

## 🤖 Ollama AI Setup (Required for AI Analysis)

AI analysis is **optional** — the rule-based engine works without Ollama.
For full AI-powered analysis, follow these steps:

### Step 1 — Install Ollama

Download and install from [ollama.com](https://ollama.com).

### Step 2 — Start Ollama Server

Open a **separate terminal** window and run:

```bash
ollama serve
```

Keep this terminal window open while using PhishGuard AI.

### Step 3 — Pull the AI Model

In another terminal, download the Llama 3.2 model (~2 GB):

```bash
ollama pull llama3.2:3b
```

This only needs to be done once. Wait for the download to complete.

### Step 4 — Verify Setup

Visit **Settings** in the PhishGuard AI dashboard, or click "Test Connection".
You should see: **Ollama — Connected ✅**

### Using a Different Model

Edit your `.env` file:
```
OLLAMA_MODEL=llama3.1:8b
```
Then restart the Flask server.

---

## 🧪 Running Tests

```bash
# Activate virtual environment first
venv\Scripts\activate   # Windows

# Run all tests
pytest tests/ -v

# Run specific test file
pytest tests/test_detection.py -v
pytest tests/test_scoring.py -v
pytest tests/test_ollama.py -v

# Run with coverage report
pip install pytest-cov
pytest tests/ --cov=app --cov-report=term-missing
```

> ℹ️ **Note:** Ollama tests use mocked HTTP calls — you do NOT need Ollama running to run tests.

---

## 📁 Project Structure

```
phishing-email-detector/
├── app/
│   ├── __init__.py              # Flask app factory
│   ├── routes.py                # All Flask routes
│   ├── database.py              # SQLite database layer
│   └── services/
│       ├── ollama_service.py    # Ollama AI client
│       ├── phishing_detector.py # Rule-based engine
│       ├── scoring.py           # Risk score calculation
│       └── validation.py        # Input validation
├── templates/                   # Jinja2 HTML templates
│   ├── base.html                # Base layout with sidebar
│   ├── dashboard.html           # Statistics dashboard
│   ├── analyze.html             # Email input form
│   ├── results.html             # Analysis result display
│   ├── history.html             # Scan history
│   ├── about.html               # Project info
│   └── settings.html            # Configuration
├── static/
│   ├── css/style.css            # Premium CSS design system
│   └── js/
│       ├── main.js              # Global utilities
│       ├── analyze.js           # Form handling
│       └── history.js           # History management
├── tests/
│   ├── test_detection.py        # Rule engine tests
│   ├── test_scoring.py          # Scoring system tests
│   └── test_ollama.py           # Mocked Ollama tests
├── docs/
│   └── architecture.md          # System architecture
├── instance/                    # SQLite database (auto-created)
├── .env.example                 # Environment variable template
├── .gitignore
├── requirements.txt
├── run.py                       # Application entry point
└── README.md
```

---

## 📊 Risk Score System

```
Final Score (0–100) = Rule Score (0–60) + AI Score (0–40)

Risk Levels:
  0–24   → LOW      (Green)   → Safe
  25–49  → MEDIUM   (Yellow)  → Suspicious
  50–74  → HIGH     (Orange)  → Suspicious
  75–100 → CRITICAL (Red)     → Malicious
```

---

## 🔒 Security & Privacy

- ✅ All email analysis is performed **locally** on your machine
- ✅ Email content is sent only to your **local** Ollama instance
- ✅ No data is sent to external servers or cloud services
- ✅ Parameterized SQL queries prevent SQL injection
- ✅ Input validation and output escaping prevent XSS
- ✅ No passwords, API keys, or database files are committed to Git

---

## ⬆️ Uploading to GitHub

> **IMPORTANT:** Never push the `.env` file, `instance/` directory (SQLite DB), or `venv/` to GitHub. These are excluded by `.gitignore`.

### Step 1 — Create Repository on GitHub

1. Go to [github.com](https://github.com) → New Repository
2. Name it `phishguard-ai` (or your preferred name)
3. Leave it **empty** (no README, no .gitignore)
4. Click **Create repository**

### Step 2 — Initialize and Push

```bash
# In your project folder:
git init
git add .
git commit -m "Initial commit: PhishGuard AI phishing detection system"

# Connect to your GitHub repository
git remote add origin https://github.com/YOUR-USERNAME/phishguard-ai.git

# Push to GitHub
git branch -M main
git push -u origin main
```

### Step 3 — Verify

Visit your GitHub repository URL and confirm the files are uploaded correctly.

---

## ⚠️ Limitations

- Designed for **educational purposes** only
- Requires Ollama for AI features (optional, rule-based works standalone)
- Does not scan email attachments
- May produce false positives (legitimate emails flagged) or false negatives (phishing missed)
- Results should always be reviewed by a human for critical security decisions
- Only plain text and simple HTML email bodies are supported

---

## 📝 License

This project is created for educational purposes as a BCA final year project.

---

## 👤 Author

- **Project:** PhishGuard AI — Phishing Email Detection System
- **Purpose:** BCA Final Year Project
- **Tech Stack:** Python, Flask, Ollama, SQLite, HTML/CSS/JS
