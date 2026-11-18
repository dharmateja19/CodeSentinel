
import ast
import hashlib
import re
from pathlib import Path
from collections import defaultdict

IGNORED_DIRS = {
    ".git", "venv", ".venv", "node_modules",
    "__pycache__", "dist", "build"
}

SOURCE_EXTENSIONS = {
    ".py", ".js", ".jsx", ".ts", ".tsx"
}

PLACEHOLDERS = {
    "pass",
    "todo",
    "fixme",
    "implement me",
    "coming soon",
    "your code here",
    "not implemented"
}


def add_finding(findings, rule_id, title, severity, path, root, line, description):
    findings.append({
        "id": rule_id,
        "title": title,
        "severity": severity,
        "file": str(path.relative_to(root)),
        "line": line,
        "description": description
    })


# ---------------- PYTHON ANALYSIS ----------------

def analyze_python_file(path: Path, root: Path) -> list:
    findings = []

    try:
        if path.stat().st_size > 1_000_000:
            return findings

        source = path.read_text(encoding="utf-8", errors="replace")
        tree = ast.parse(source)
        lines = source.splitlines()

        for node in ast.walk(tree):
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                meaningful = [
                    n for n in node.body
                    if not (
                        isinstance(n, ast.Expr)
                        and isinstance(n.value, ast.Constant)
                        and isinstance(n.value.value, str)
                    )
                ]

                if len(meaningful) == 1 and isinstance(
                    meaningful[0], ast.Pass
                ):
                    add_finding(
                        findings, "SLP001", "Empty function",
                        "LOW", path, root, node.lineno,
                        f"Function '{node.name}' contains no implementation."
                    )

                if len(node.body) > 40:
                    add_finding(
                        findings, "SLP002", "Oversized function",
                        "MEDIUM", path, root, node.lineno,
                        f"Function '{node.name}' has many statements."
                    )

        for number, line in enumerate(lines, start=1):
            stripped = line.strip().lower().lstrip("#").strip()

            if any(word in stripped for word in PLACEHOLDERS):
                add_finding(
                    findings, "SLP003", "Placeholder or boilerplate",
                    "LOW", path, root, number,
                    "Potential placeholder or unfinished code."
                )

    except (SyntaxError, UnicodeError, OSError, ValueError):
        pass

    return findings


# ---------------- JAVASCRIPT / TYPESCRIPT ANALYSIS ----------------

def analyze_javascript_file(path: Path, root: Path) -> list:
    findings = []

    try:
        if path.stat().st_size > 1_000_000:
            return findings

        source = path.read_text(encoding="utf-8", errors="replace")
        relative_path = str(path.relative_to(root))

        # 1. Empty function declarations and expressions
        patterns = [
            r"\bfunction\s*[\w$]*\s*\([^)]*\)\s*\{\s*\}",
            r"=>\s*\{\s*\}"
        ]

        for pattern in patterns:
            for match in re.finditer(pattern, source):
                line = source.count("\n", 0, match.start()) + 1
                add_finding(
                    findings, "SLP001", "Empty function",
                    "LOW", path, root, line,
                    "Function appears to have an empty implementation."
                )

        # 2. Oversized functions (heuristic)
        function_pattern = re.compile(
            r"\bfunction\s*[\w$]*\s*\([^)]*\)\s*\{"
        )

        for match in function_pattern.finditer(source):
            start = match.end()
            depth = 1
            position = start

            while position < len(source) and depth > 0:
                if source[position] == "{":
                    depth += 1
                elif source[position] == "}":
                    depth -= 1
                position += 1

            if depth == 0:
                body = source[start:position - 1]
                statement_count = sum(
                    1 for line in body.splitlines() if line.strip()
                )

                if statement_count > 40:
                    line = source.count("\n", 0, match.start()) + 1
                    add_finding(
                        findings, "SLP002", "Oversized function",
                        "MEDIUM", path, root, line,
                        "Function contains more than 40 non-empty lines."
                    )

        # 3. Placeholder detection
        for number, line in enumerate(source.splitlines(), start=1):
            stripped = line.strip().lower()

            if stripped.startswith(("//", "*", "/*")):
                stripped = re.sub(r"^(//|/\*|\*)\s*", "", stripped)

            if any(word in stripped for word in PLACEHOLDERS):
                add_finding(
                    findings, "SLP003", "Placeholder or boilerplate",
                    "LOW", path, root, number,
                    "Potential placeholder or unfinished code."
                )

    except (OSError, UnicodeError, ValueError):
        pass

    return findings


# ---------------- DUPLICATE LINE DETECTION ----------------

def detect_duplicate_lines(root: Path) -> list:
    occurrences = defaultdict(list)

    for path in root.rglob("*"):
        if not path.is_file() or path.is_symlink():
            continue

        if any(
            part in IGNORED_DIRS
            for part in path.relative_to(root).parts
        ):
            continue

        if path.suffix.lower() not in SOURCE_EXTENSIONS:
            continue

        try:
            if path.stat().st_size > 1_000_000:
                continue

            lines = path.read_text(
                encoding="utf-8", errors="replace"
            ).splitlines()

            for number, line in enumerate(lines, start=1):
                normalized = " ".join(line.split())

                if len(normalized) < 30:
                    continue

                if normalized.startswith(("#", "//", "*")):
                    continue

                digest = hashlib.sha256(
                    normalized.encode()
                ).hexdigest()

                occurrences[digest].append((path, number))

        except (OSError, ValueError):
            continue

    findings = []

    for locations in occurrences.values():
        if len(locations) < 3:
            continue

        path, line = locations[0]

        findings.append({
            "id": "SLP004",
            "title": "Repeated code line",
            "severity": "LOW",
            "file": str(path.relative_to(root)),
            "line": line,
            "description": (
                f"Same non-trivial line occurs {len(locations)} times."
            )
        })

    return findings


# ---------------- REPOSITORY ANALYSIS ----------------

def analyze_slop(repo_path: str) -> dict:
    root = Path(repo_path).expanduser().resolve()

    if not root.exists() or not root.is_dir():
        raise ValueError("Invalid repository directory")

    findings = []

    for path in root.rglob("*"):
        if not path.is_file() or path.is_symlink():
            continue

        if any(
            part in IGNORED_DIRS
            for part in path.relative_to(root).parts
        ):
            continue

        suffix = path.suffix.lower()

        if suffix == ".py":
            findings.extend(analyze_python_file(path, root))

        elif suffix in {".js", ".jsx", ".ts", ".tsx"}:
            findings.extend(analyze_javascript_file(path, root))

    findings.extend(detect_duplicate_lines(root))

    return {
        "category": "Slop",
        "total_findings": len(findings),
        "findings": findings
    }
