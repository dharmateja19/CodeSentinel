
import json
import re
import shutil
import subprocess
from pathlib import Path

from app.scanner.language_detector import detect_language


IGNORED_DIRS = {
    ".git", "venv", ".venv", "node_modules",
    "__pycache__", "dist", "build", ".next",
    "coverage", ".idea", ".vscode"
}

MAX_FILE_SIZE = 1_000_000


# Rules applicable across supported source languages.
COMMON_RULES = [
    {
        "id": "SEC001",
        "name": "Hardcoded credentials",
        "severity": "HIGH",
        "pattern": re.compile(
            r"""(?i)\b(password|passwd|api_key|secret_key|access_token|client_secret)\b"""
            r"""\s*[:=]\s*["'][^"'\s]{4,}["']"""
        ),
        "description": "Possible hardcoded credential. Use environment variables or a secrets manager.",
        "extensions": None
    }
]


PYTHON_RULES = [
    {
        "id": "SEC002",
        "name": "Dangerous dynamic execution",
        "severity": "HIGH",
        "pattern": re.compile(r"\b(?:eval|exec)\s*\("),
        "description": "Dynamic code execution can execute untrusted input.",
        "extensions": {".py"}
    },
    {
        "id": "SEC003",
        "name": "Command injection risk",
        "severity": "HIGH",
        "pattern": re.compile(
            r"\bsubprocess\.(?:run|call|Popen)\s*\(.*shell\s*=\s*True"
        ),
        "description": "Shell execution with shell=True can introduce command injection.",
        "extensions": {".py"}
    },
    {
        "id": "SEC004",
        "name": "Unsafe deserialization",
        "severity": "HIGH",
        "pattern": re.compile(r"\bpickle\.loads?\s*\("),
        "description": "Deserializing untrusted pickle data can execute arbitrary code.",
        "extensions": {".py"}
    },
    {
        "id": "SEC005",
        "name": "Weak cryptographic hash",
        "severity": "MEDIUM",
        "pattern": re.compile(
            r"\b(?:hashlib\.)?(?:md5|sha1)\s*\("
        ),
        "description": "MD5 and SHA1 are unsuitable for security-sensitive hashing.",
        "extensions": {".py"}
    },
    {
        "id": "SEC006",
        "name": "Possible SQL injection",
        "severity": "HIGH",
        "pattern": re.compile(
            r"""(?i)(?:execute|executemany)\s*\(\s*(?:f["']|["'][^"']*["']\s*\+)"""
        ),
        "description": "SQL query may be constructed using string interpolation or concatenation.",
        "extensions": {".py"}
    }
]


JAVASCRIPT_RULES = [
    {
        "id": "SEC007",
        "name": "Dangerous JavaScript execution",
        "severity": "HIGH",
        "pattern": re.compile(
            r"\beval\s*\(|\bnew\s+Function\s*\("
        ),
        "description": "Dynamic JavaScript execution can execute untrusted code.",
        "extensions": {".js", ".jsx", ".ts", ".tsx"}
    },
    {
        "id": "SEC008",
        "name": "Potential DOM-based XSS",
        "severity": "HIGH",
        "pattern": re.compile(
            r"""(?i)(?:\.innerHTML|\.outerHTML)\s*=\s*.*"""
            r"""(?:location|location\.search|location\.hash|URLSearchParams|\.searchParams)"""
        ),
        "description": "Untrusted URL-derived data may be inserted into HTML without sanitization.",
        "extensions": {".js", ".jsx", ".ts", ".tsx"}
    },
    {
        "id": "SEC009",
        "name": "Potential command injection",
        "severity": "HIGH",
        "pattern": re.compile(
            r"""\b(?:exec|execSync)\s*\(\s*(?:`[^`]*\$\{|[^)]*\+\s*[A-Za-z_$])"""
        ),
        "description": "A command may be constructed using dynamic input. Verify whether untrusted data reaches the command.",
        "extensions": {".js", ".jsx", ".ts", ".tsx"}
    },
    {
        "id": "SEC010",
        "name": "Potential SQL injection",
        "severity": "HIGH",
        "pattern": re.compile(
            r"""\.(?:query|execute)\s*\(\s*`[^`]*\$\{"""
        ),
        "description": "SQL query may contain interpolated values. Use parameterized queries.",
        "extensions": {".js", ".jsx", ".ts", ".tsx"}
    },
    {
        "id": "SEC011",
        "name": "Unsafe HTML insertion",
        "severity": "HIGH",
        "pattern": re.compile(
            r"\bdangerouslySetInnerHTML\s*="
        ),
        "description": "React dangerouslySetInnerHTML bypasses normal escaping. Ensure HTML is trusted and sanitized.",
        "extensions": {".js", ".jsx", ".ts", ".tsx"}
    }
]


HTML_RULES = [
    {
        "id": "SEC012",
        "name": "JavaScript URL detected",
        "severity": "HIGH",
        "pattern": re.compile(
            r"""(?i)(?:href|src)\s*=\s*["']\s*javascript\s*:"""
        ),
        "description": "JavaScript URLs can execute script when activated.",
        "extensions": {".html"}
    },
    {
        "id": "SEC013",
        "name": "Potential unsafe document.write",
        "severity": "MEDIUM",
        "pattern": re.compile(
            r"""(?i)document\.write\s*\(\s*(?:location|window\.location)"""
        ),
        "description": "Writing URL-derived content directly into a document can introduce cross-site scripting.",
        "extensions": {".html"}
    }
]


CSS_RULES = [
    {
        "id": "SEC014",
        "name": "Legacy CSS expression detected",
        "severity": "MEDIUM",
        "pattern": re.compile(
            r"(?i)expression\s*\("
        ),
        "description": "Legacy CSS expressions can execute dynamic expressions in older browser environments.",
        "extensions": {".css"}
    },
    {
        "id": "SEC015",
        "name": "JavaScript URL in CSS",
        "severity": "HIGH",
        "pattern": re.compile(
            r"""(?i)url\s*\(\s*["']?\s*javascript\s*:"""
        ),
        "description": "JavaScript URLs in CSS are suspicious and may create script execution risks.",
        "extensions": {".css"}
    }
]


ALL_RULES = (
    COMMON_RULES
    + PYTHON_RULES
    + JAVASCRIPT_RULES
    + HTML_RULES
    + CSS_RULES
)


def should_ignore(file_path: Path, root: Path) -> bool:
    try:
        relative_path = file_path.relative_to(root)

        return any(
            part in IGNORED_DIRS
            for part in relative_path.parts
        )

    except ValueError:
        return True


def scan_custom_rules(root: Path) -> list:
    findings = []

    for file_path in root.rglob("*"):

        if not file_path.is_file() or file_path.is_symlink():
            continue

        if should_ignore(file_path, root):
            continue

        language = detect_language(file_path)

        if language == "Unknown":
            continue

        try:
            if file_path.stat().st_size > MAX_FILE_SIZE:
                continue

            lines = file_path.read_text(
                encoding="utf-8",
                errors="replace"
            ).splitlines()

            extension = file_path.suffix.lower()

            for line_number, line in enumerate(lines, start=1):

                for rule in ALL_RULES:

                    allowed_extensions = rule["extensions"]

                    if (
                        allowed_extensions is not None
                        and extension not in allowed_extensions
                    ):
                        continue

                    if rule["pattern"].search(line):
                        findings.append({
                            "id": rule["id"],
                            "title": rule["name"],
                            "severity": rule["severity"],
                            "file": file_path.relative_to(root).as_posix(),
                            "line": line_number,
                            "evidence": "[Sensitive or potentially unsafe code omitted]",
                            "description": rule["description"],
                            "source": "Custom Security Rules"
                        })

        except (OSError, ValueError):
            continue

    return findings


def run_bandit(root: Path) -> list:
    if not shutil.which("bandit"):
        return []

    try:
        result = subprocess.run(
            [
                "bandit",
                "-r",
                str(root),
                "-f",
                "json",
                "-q",
                "-x",
                "*/venv/*,*/.venv/*,*/node_modules/*,*/.git/*,*/dist/*,*/build/*"
            ],
            capture_output=True,
            text=True,
            timeout=60,
            check=False
        )

        if not result.stdout.strip():
            return []

        data = json.loads(result.stdout)
        findings = []

        for issue in data.get("results", []):

            findings.append({
                "id": issue.get("test_id"),
                "title": issue.get("test_name"),
                "severity": issue.get("issue_severity", "LOW").upper(),
                "file": issue.get("filename"),
                "line": issue.get("line_number"),
                "evidence": "[Code excerpt omitted]",
                "description": issue.get("issue_text"),
                "source": "Bandit"
            })

        return findings

    except (
        subprocess.TimeoutExpired,
        json.JSONDecodeError,
        OSError
    ):
        return []


def analyze_security(repo_path: str) -> dict:
    root = Path(repo_path).expanduser().resolve()

    if not root.exists() or not root.is_dir():
        raise ValueError("Invalid repository directory")

    custom_findings = scan_custom_rules(root)
    bandit_findings = run_bandit(root)

    findings = custom_findings + bandit_findings

    return {
        "category": "Security",
        "total_findings": len(findings),
        "findings": findings,
        "tools_used": [
            "Custom Security Rules",
            "Bandit (Python)"
        ]
    }
