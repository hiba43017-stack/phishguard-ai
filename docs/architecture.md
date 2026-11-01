# PhishGuard AI — System Architecture

## Overview

PhishGuard AI is a Flask-based web application that combines rule-based
phishing detection with AI-powered analysis using Ollama (local LLMs).

## Architecture Diagram

```
┌────────────────────────────────────────────────────────────┐
│                        Browser (User)                       │
│              HTML / CSS / JavaScript Frontend               │
└──────────────────────────┬─────────────────────────────────┘
                           │ HTTP (localhost:5000)
┌──────────────────────────▼─────────────────────────────────┐
│                     Flask Web Server                        │
│                     app/routes.py                           │
│                                                             │
│  GET  /              → dashboard.html                       │
│  GET  /analyze       → analyze.html                         │
│  POST /api/analyze   → Analysis pipeline (JSON API)         │
│  GET  /results/<id>  → results.html                         │
│  GET  /history       → history.html                         │
│  GET  /about         → about.html                           │
│  GET  /settings      → settings.html                        │
└──────────┬───────────────────────┬──────────────────────────┘
           │                       │
┌──────────▼──────┐   ┌────────────▼─────────────────────────┐
│  SQLite DB       │   │         Detection Pipeline            │
│  (instance/      │   │                                       │
│   phishing.db)   │   │  1. validation.py   (input check)    │
│                  │   │  2. phishing_detector.py (rules)      │
│  - scans table   │   │  3. ollama_service.py (AI)            │
│  - CRUD ops      │   │  4. scoring.py   (combine+score)      │
└──────────────────┘   └────────────┬─────────────────────────┘
                                    │ HTTP (localhost:11434)
                       ┌────────────▼─────────────────────────┐
                       │           Ollama Local Server         │
                       │       Model: llama3.2:3b              │
                       │   (runs on user's machine, private)   │
                       └──────────────────────────────────────┘
```

## Component Details

### app/__init__.py — Flask App Factory
- Creates Flask instance with configuration from .env
- Initializes database on startup
- Registers blueprints

### app/routes.py — Route Handlers
- Page routes: render Jinja2 templates with data from DB
- API routes: JSON endpoints for AJAX interactions
- Error handlers: 404 and 500 pages

### app/database.py — Data Layer
- SQLite with parameterized queries (SQL injection prevention)
- `scans` table stores all analysis results as JSON fields
- Functions: save_scan, get_scan_by_id, search_scans, get_dashboard_stats

### app/services/validation.py
- Input sanitization and length limits
- Email format validation (bare address + display name formats)
- Returns (is_valid, errors) tuple

### app/services/phishing_detector.py — Rule Engine
Checks applied (max 60 points total):
| Check | Max Points | Description |
|-------|-----------|-------------|
| URGENCY_LANGUAGE | 10 | Urgent/threatening words |
| CREDENTIAL_REQUEST | 15 | Password/OTP/PIN requests |
| PAYMENT_LURE | 10 | Financial deception |
| IP_BASED_URL | 12 | Raw IP in URLs |
| URL_SHORTENER | 8 | bit.ly, tinyurl etc. |
| SUSPICIOUS_TLD | 10 | .xyz, .tk, .ml etc. |
| FREE_HOSTING_URL | 7 | webhost services abused |
| MISLEADING_LINK | 12 | URL text ≠ href |
| SENSITIVE_INFO_REQUEST | 15 | SSN, bank account |
| BRAND_DOMAIN_MISMATCH | 15 | PayPal claimed, gmail sent |
| BRAND_IMPERSONATION | 5 | Brand mention |
| SUSPICIOUS_SENDER | 8 | Service name + free domain |
| FREE_EMAIL_SENDER | 4 | Gmail/Yahoo for official |
| ALL_CAPS_SUBJECT | 4 | SHOUTING SUBJECT |
| FAKE_REPLY_FORWARD | 5 | Re:/Fwd: tricks |
| HIDDEN_HTML_CONTENT | 8 | display:none tricks |
| EXCESSIVE_PUNCTUATION | 3 | !!!! or CAPS blocks |

### app/services/ollama_service.py — AI Integration
- Sends email to Ollama via HTTP POST /api/generate
- Structured JSON prompt requesting verdict/reasons/evidence/confidence
- Parses JSON from AI response (handles markdown fences)
- Validates and sanitizes AI response fields
- Graceful timeout and connection error handling

### app/services/scoring.py — Risk Score Calculator
```
Final Score = min(rule_score, 60) + ai_score
ai_score = min(40, base_verdict_bonus × confidence_scale)
  where base = {Malicious:40, Suspicious:20, Safe:0}
  and scale = max(0.5, confidence/100)
```

## Security Considerations
1. All DB queries use parameterized SQL
2. Output is HTML-escaped by Jinja2 auto-escaping
3. Input is length-limited and sanitized
4. Email body is sent only to localhost (Ollama)
5. No URL auto-opening or email auto-sending
6. Secret key must be changed in production (.env)
