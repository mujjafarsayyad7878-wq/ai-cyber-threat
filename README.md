# 🛡️ CyberShield AI - AI Cyber Threat & Phishing Detection Engine

[![Python](https://img.shields.io/badge/Python-3.10%2B-blue.svg)](https://www.python.org/)
[![FastAPI](https://img.shields.io/badge/FastAPI-0.104%2B-009688.svg)](https://fastapi.tiangolo.com/)
[![Scikit-Learn](https://img.shields.io/badge/Scikit--Learn-1.3%2B-F7931E.svg)](https://scikit-learn.org/)
[![Tailwind CSS](https://img.shields.io/badge/Tailwind_CSS-3.0%2B-38B2AC.svg)](https://tailwindcss.com/)
[![Deploy to Render](https://render.com/images/deploy-to-render-button.svg)](https://render.com)

A high-performance, dark-themed cyber threat intelligence web application designed to detect and neutralize email phishing scams, SMS lures, and deceptive URLs using probabilistic machine learning (TF-IDF + Multinomial Naive Bayes) alongside deep URL heuristic parsing.

---

## 🌟 Key Features

- **Hybrid AI & Heuristic Detection Architecture**:
  - **NLP Classifier**: Scikit-Learn `TfidfVectorizer` (unigrams & bigrams) coupled with `MultinomialNB` (&alpha;=0.1) for probabilistic text analysis.
  - **URL Vector Heuristics**: RFC 3986 parsing with naked IP detection, brand impersonation / typosquatting checks, URL shortener resolution, suspicious TLD profiling (`.xyz`, `.top`, `.tk`), deep subdomain inspection, and userinfo `@` symbol exploitation detection.
  - **Psychological Trigger Scoring**: Regex-based urgency and coercion scoring for account suspension threats, password harvests, and gift card / tax refund lures.
- **Dynamic Risk Gauge (0 - 100)**:
  - Interactive **Chart.js** semi-doughnut risk meter displaying **Safe (0–35)**, **Suspicious (36–70)**, and **Malicious (71–100)** threat levels.
- **Pre-Configured Quick Test Samples**:
  - Instant 1-click test cases: PayPal Suspended Account Phishing, Naked IP Harvester, Bit.ly Gift Card Lottery, and Safe Corporate Standup.
- **Dedicated ML Analytics Page (`/analytics`)**:
  - Live model accuracy, precision, recall, F1 score, 2x2 interactive confusion matrix, and top TF-IDF feature importance bar charts.
- **Technical Architecture Guide (`/about`)**:
  - Deep-dive into Bayes' theorem, RFC 3986 heuristics, and SOC incident response containment playbooks.
- **Free Cloud Ready**:
  - Pre-configured with `render.yaml` and `Procfile` for immediate one-click free hosting on Render.

---

## 📂 Project Structure

```text
├── main.py              # FastAPI backend, ML model, URL heuristics & API routes
├── requirements.txt     # Python production dependencies
├── Procfile             # Render / Heroku process declaration
├── render.yaml          # Render Blueprint deployment specification
├── .gitignore           # Git ignore rules
├── README.md            # Project documentation & setup instructions
├── templates/
│   ├── index.html       # Home page & live detector dashboard
│   ├── analytics.html   # ML analytics, confusion matrix & feature importance
│   └── about.html       # Technical documentation & SOC incident response
└── static/              # Static assets
```

---

## 🚀 Local Development Setup

### 1. Clone the repository
```bash
git clone https://github.com/your-username/ai-cyber-threat-detector.git
cd ai-cyber-threat-detector
```

### 2. Create a virtual environment & install dependencies
```bash
# Create virtual environment
python -m venv venv

# Activate virtual environment
# Windows:
venv\Scripts\activate
# Linux/macOS:
source venv/bin/activate

# Install required dependencies
pip install -r requirements.txt
```

### 3. Start the application
```bash
uvicorn main:app --reload --host 127.0.0.1 --port 8000
```

Open your browser and navigate to:
- **Live Detector**: [http://127.0.0.1:8000](http://127.0.0.1:8000)
- **ML Analytics**: [http://127.0.0.1:8000/analytics](http://127.0.0.1:8000/analytics)
- **Technical Architecture**: [http://127.0.0.1:8000/about](http://127.0.0.1:8000/about)
- **Interactive OpenAPI Docs**: [http://127.0.0.1:8000/docs](http://127.0.0.1:8000/docs)

---

## 📡 API Endpoints

| Method | Endpoint | Description |
| :--- | :--- | :--- |
| `GET` | `/` | Renders Home Page & Live Detector Dashboard |
| `GET` | `/analytics` | Renders ML Model Telemetry & Confusion Matrix |
| `GET` | `/about` | Renders Technical Architecture & Mitigation SOP |
| `POST` | `/api/analyze` | Accepts `{ text: string, url: string }` and returns composite risk score, breakdown flags, and mitigations |
| `GET` | `/api/analytics` | Returns model validation metrics, top TF-IDF features, and recent scans |
| `GET` | `/api/sample-data` | Returns pre-built phishing and safe test cases |
| `GET` | `/api/health` | Returns service health status and timestamp |

---

## ☁️ Free Deployment on Render

### Step 1: Push code to GitHub
```bash
git init
git add .
git commit -m "Initial commit of AI Cyber Threat Detection Engine"
git branch -M main
git remote add origin https://github.com/<your-username>/<your-repo-name>.git
git push -u origin main
```

### Step 2: Deploy on Render
1. Log in to [Render.com](https://render.com).
2. In the dashboard, click **New +** &rarr; **Web Service**.
3. Select your connected GitHub repository.
4. Fill in the service configuration:
   - **Name**: `ai-cyber-threat-detector`
   - **Environment**: `Python 3`
   - **Region**: Oregon (or your preferred region)
   - **Branch**: `main`
   - **Build Command**: `pip install -r requirements.txt`
   - **Start Command**: `uvicorn main:app --host 0.0.0.0 --port $PORT`
   - **Instance Type**: **Free**
5. Click **Create Web Service**.
6. Render will automatically build the environment, install dependencies, train the model on startup, and launch your live application at `https://<your-service>.onrender.com`!
