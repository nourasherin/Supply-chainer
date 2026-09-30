# Supplychainer

### AI-Powered Disruption-Aware Supply Chain Routing

Supplychainer is an intelligent supply-chain decision platform designed to help logistics teams make disruption-aware routing decisions using global disruption intelligence, threat analysis, machine-learning-based delay risk, and multimodal route optimization.

## Problem

Global supply chains are vulnerable to disruptions such as canal blockages, port closures, geopolitical events, extreme weather, and transportation delays. Traditional routing systems may identify disruptions without fully incorporating their impact into route selection.

Supplychainer addresses this by integrating disruption intelligence and risk estimates directly into route recommendation.

## Key Features

* **Disruption-Aware Routing** – Active disruptions influence route selection.
* **SUEZ_BLOCK Scenario Simulation** – Demonstrates rerouting when the Suez Canal is disrupted.
* **Context-Aware Relevance Filtering (CARF)** – Filters disruption information for route relevance.
* **Threat Intelligence** – Analyzes disruption signals and generates threat information.
* **Quantile ML Risk Analysis** – Uses p85 delay risk to provide a conservative estimate of potential delay.
* **Multimodal Routing** – Considers different transportation modes and strategic handoffs.
* **Decision Integrity Audit** – Displays transit time, transfer time, scenario impact, risk buffer, and cost composition.
* **Route Trade-off Analysis** – Provides fastest and cost-oriented routing alternatives.

## SUEZ Blockage Demonstration

The platform can simulate a Suez Canal blockage using the `SUEZ_BLOCK` scenario.

When the disruption is activated, the routing engine incorporates the disruption into the optimization process and avoids the affected corridor. The demonstrated alternative maritime route uses:

**Shanghai → Singapore → Colombo → Durban → Algeciras → Rotterdam**

The dashboard also provides an audit trail showing the scenario impact and risk calculations behind the recommendation.

## System Architecture

```text
Global Disruption / News Signals
            ↓
Context-Aware Relevance Filter
            ↓
Threat Intelligence & NLP
            ↓
Quantile ML Risk Estimation
            ↓
Disruption-Aware Route Optimization
            ↓
Fastest / Balanced Recommendations
            ↓
Decision Integrity Audit
            ↓
Executive Command Dashboard
```

## Technology Stack

### Backend

* Python
* FastAPI
* NumPy
* Machine Learning / NLP components

### Frontend

* React
* Vite
* JavaScript
* CSS

### AI / ML

* Context-Aware Relevance Filtering
* NLP-based threat analysis
* Quantile-based delay risk estimation
* p85 risk buffer
* Scenario-aware route optimization

## Project Structure

```text
Supply-chainer/
├── backend/
│   ├── engine/
│   └── main.py
├── frontend/
│   ├── src/
│   └── package.json
├── scratch/
├── requirements.txt
└── README.md
```

## Running Locally

### Backend

Create and activate a Python virtual environment, install the dependencies, and start the FastAPI server:

```bash
pip install -r requirements.txt
uvicorn backend.main:app --host 127.0.0.1 --port 8000
```

### Frontend

```bash
cd frontend
npm install
npm run dev
```

Open the application at:

```text
http://localhost:5173
```

Backend API documentation:

```text
http://127.0.0.1:8000/docs
```

## AI-Assisted Development Disclosure

AI-assisted development tools were used during the development process, including **ChatGPT** and **Google Antigravity**, for debugging, code analysis, implementation assistance, troubleshooting, and development support.

All AI-assisted changes were reviewed, tested, and validated by the team as part of the final implementation.

## Hackathon

Developed for **TatHack'26 – Tathva, NIT Calicut**.

## Team

Supplychainer was developed as a hackathon project by the registered team members.
