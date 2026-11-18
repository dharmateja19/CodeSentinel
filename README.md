# 🛡️ CodeSentinel
### AI-Powered Code Security & Quality Auditor

CodeSentinel is an AI-assisted code auditing platform that analyzes software repositories to identify potential security vulnerabilities, coding gaps, unfinished implementations, and code-quality issues.

It combines static analysis techniques with AI-powered validation to provide developers with actionable findings, explanations, potential impacts, and recommended fixes.

## ✨ Features

### 1. Security Analysis
- Detects potential hardcoded credentials.
- Identifies potentially unsafe function usage.
- Detects potential SQL injection patterns.
- Identifies DOM-based XSS risks.
- Checks selected JavaScript, HTML, CSS and Python security patterns.

### 2. Code Slop Detection
- Identifies empty function implementations.
- Detects oversized functions.
- Finds placeholder and boilerplate code.
- Identifies repeated code lines.

### 3. Coding Gap Analysis
- Detects potentially unused imports and variables.
- Identifies functions with excessive parameters.
- Detects mutable default arguments in Python.
- Identifies bare exception handling.
- Checks selected JavaScript/TypeScript coding patterns.
- Analyzes Python cyclomatic complexity.

### 4. Loose Ends Detection
- Finds unresolved TODO, FIXME, XXX, HACK and BUG comments.
- Detects unimplemented functionality.
- Identifies empty function implementations.

### 5. AI-Powered Validation
- Validates static analysis findings using an LLM.
- Classifies findings as Confirmed, Likely, False Positive or Uncertain.
- Provides reasoning and potential impact.
- Recommends actionable fixes.
- Includes confidence scores and AI provider information.

### 6. Interactive Dashboard
- Repository analysis overview.
- Severity-based finding summaries.
- AI validation statistics.
- Search and filter findings by category and severity.
- Expandable finding details.
- Downloadable JSON audit reports.

## 🧰 Tech Stack

| Component | Technologies |
|---|---|
| Frontend | React.js, Vite, Tailwind CSS |
| Backend | Python, FastAPI |
| Static Analysis | Python AST, Regex, Bandit, Radon |
| AI Integration | Google Gemini, Ollama |
| AI Models | Gemini models, Qwen2.5-Coder |
| API Communication | REST API |
| Version Control | Git, GitHub |

## 🏗️ Architecture

```text
                  CodeSentinel
                       |
                React Dashboard
                       |
                  FastAPI Backend
                       |
               Repository Scanner
                       |
          +------------+------------+
          |            |            |
       Security      Code Slop   Coding Gaps
       Analyzer      Analyzer     Analyzer
          |            |            |
          +------------+------------+
                       |
                Loose Ends Analyzer
                       |
                Finding Deduplication
                       |
                 AI Validation
                       |
              Gemini / Ollama LLM
                       |
                Audit Aggregation
                       |
                JSON API Response
                       |
                React Dashboard
```

## 📂 Project Structure

```text
CodeSentinel/
│
├── app/
│   ├── main.py
│   │
│   ├── scanner/
│   │   ├── repository.py
│   │   ├── language_detector.py
│   │   └── github.py
│   │
│   ├── analyzers/
│   │   ├── security.py
│   │   ├── slop.py
│   │   ├── coding_gaps.py
│   │   └── loose_ends.py
│   │
│   └── agent/
│       ├── auditor.py
│       ├── reasoner.py
│       └── llm.py
│
├── frontend/
│   ├── src/
│   │   ├── App.jsx
│   │   └── index.css
│   ├── package.json
│   └── vite.config.js
│
├── sample_projects/
│
├── requirements.txt
├── .gitignore
├── .env.example
└── README.md
```

## ⚙️ Installation & Setup

### Prerequisites

- Python 3.10+
- Node.js and npm
- Git
- Ollama (if using local LLM inference)

### 1. Clone the Repository

```bash
git clone https://github.com/dharmateja19/CodeSentinel.git
cd CodeSentinel
```

### 2. Backend Setup

Create and activate a virtual environment.

**Windows:**

```powershell
python -m venv venv
.\venv\Scripts\Activate.ps1
```

**Linux / macOS:**

```bash
python -m venv venv
source venv/bin/activate
```

Install dependencies:

```bash
pip install -r requirements.txt
```

### 3. Configure Environment Variables

Create a `.env` file in the project root.

```env
AI_PROVIDER=ollama

GEMINI_API_KEY=your_gemini_api_key
GEMINI_MODEL=your_gemini_model

OLLAMA_HOST=http://localhost:11434
OLLAMA_MODEL=qwen2.5-coder:1.5b
```

Configure the provider and model according to your setup. Keep API keys private and never commit your `.env` file.

### 4. Run the Backend

```bash
uvicorn app.main:app --reload
```

Backend:

```text
http://127.0.0.1:8000
```

API documentation:

```text
http://127.0.0.1:8000/docs
```

### 5. Frontend Setup

Open another terminal:

```bash
cd frontend
npm install
npm run dev
```

Frontend:

```text
http://localhost:5173
```

## 🚀 How to Use

1. Start the FastAPI backend.
2. Start the React frontend.
3. Open the dashboard in your browser.
4. Enter a local repository path or supported public GitHub repository URL.
5. Click **Run Full Audit**.
6. Review the security, code-quality, coding-gap and loose-end findings.
7. Expand findings to view AI reasoning, impact and recommended fixes.
8. Download the complete audit report in JSON format.

## 📊 Finding Categories

| Category | Purpose |
|---|---|
| Security | Potential security vulnerabilities |
| Slop | Placeholder, repetitive and low-quality code |
| Coding Gaps | Potential implementation and maintainability issues |
| Loose Ends | Unfinished tasks and unimplemented functionality |

Findings are classified by severity:

- **Critical** – Immediate attention required.
- **High** – Significant potential risk.
- **Medium** – Requires review and improvement.
- **Low** – Minor issue or improvement opportunity.
- **Info** – Informational observation.

AI validation verdicts include Confirmed, Likely, False Positive and Uncertain.

## 🔍 Supported Languages

The repository scanner recognizes Python, JavaScript, JSX, TypeScript, TSX, Java, C, C++, Go, Rust, PHP, Ruby, C#, Swift, Kotlin, HTML, CSS, SQL and Shell.

**Note:** Language recognition does not mean every analyzer supports every language. Python has the broadest analysis coverage. JavaScript and TypeScript have additional heuristic checks, while other languages currently have more limited rule coverage.

## 🔐 Security & Limitations

- Static analysis uses rule-based and heuristic detection.
- AI validation assists with interpreting findings but does not guarantee correctness.
- Some findings may be false positives or missed vulnerabilities.
- The current implementation does not provide comprehensive semantic analysis for every supported language.
- AI-generated recommendations should be reviewed before applying them.
- Never expose API keys, credentials or sensitive repository data.

## 🎯 Project Objective

The objective of CodeSentinel is to make repository auditing more accessible by combining traditional static analysis with AI-assisted reasoning.

Rather than simply reporting suspicious code patterns, CodeSentinel aims to help developers understand potential issues, assess their impact and identify practical improvements.

## 👨‍💻 Author

Developed as a hackathon project for **Mycrobo Arena**.

---

**CodeSentinel — Detect. Analyze. Improve.**