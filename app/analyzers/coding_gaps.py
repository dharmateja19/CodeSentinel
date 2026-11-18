
import ast
import re
from pathlib import Path
from collections import Counter
from radon.complexity import cc_visit

IGNORED_DIRS = {
    ".git", "venv", ".venv", "node_modules",
    "__pycache__", "dist", "build"
}

JS_EXTENSIONS = {".js", ".jsx", ".ts", ".tsx"}


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

        # 1. Bare except
        for node in ast.walk(tree):
            if isinstance(node, ast.ExceptHandler) and node.type is None:
                add_finding(
                    findings, "GAP001", "Bare except block",
                    "MEDIUM", path, root, node.lineno,
                    "Catching every exception can hide unexpected errors."
                )

        # 2. Mutable defaults and too many arguments
        for node in ast.walk(tree):
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                defaults = node.args.defaults + [
                    d for d in node.args.kw_defaults if d is not None
                ]

                for default in defaults:
                    if isinstance(default, (ast.List, ast.Dict, ast.Set)):
                        add_finding(
                            findings, "GAP002", "Mutable default argument",
                            "MEDIUM", path, root, default.lineno,
                            f"Function '{node.name}' uses a mutable default argument."
                        )

                arg_count = (
                    len(node.args.posonlyargs)
                    + len(node.args.args)
                    + len(node.args.kwonlyargs)
                )

                if node.args.vararg:
                    arg_count += 1
                if node.args.kwarg:
                    arg_count += 1

                if arg_count > 6:
                    add_finding(
                        findings, "GAP003", "Too many function arguments",
                        "LOW", path, root, node.lineno,
                        f"Function '{node.name}' has more than six arguments."
                    )

        # 3. Unused imports
        imported_names = {}

        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                for alias in node.names:
                    name = alias.asname or alias.name.split(".")[0]
                    imported_names[name] = node.lineno

            elif isinstance(node, ast.ImportFrom):
                for alias in node.names:
                    name = alias.asname or alias.name
                    if name != "*":
                        imported_names[name] = node.lineno

        loaded_names = {
            node.id for node in ast.walk(tree)
            if isinstance(node, ast.Name)
            and isinstance(node.ctx, ast.Load)
        }

        for name, line in imported_names.items():
            if name not in loaded_names:
                add_finding(
                    findings, "GAP004", "Potentially unused import",
                    "LOW", path, root, line,
                    f"Imported name '{name}' is not referenced."
                )

        # 4. Unused variables
        assigned = Counter()
        loaded = Counter()
        assignment_lines = {}

        for node in ast.walk(tree):
            if isinstance(node, ast.Name):
                if isinstance(node.ctx, ast.Store):
                    assigned[node.id] += 1
                    assignment_lines[node.id] = node.lineno
                elif isinstance(node.ctx, ast.Load):
                    loaded[node.id] += 1

        for name, count in assigned.items():
            if name.startswith("_"):
                continue

            if count == 1 and loaded[name] == 0:
                add_finding(
                    findings, "GAP005", "Potentially unused variable",
                    "LOW", path, root, assignment_lines[name],
                    f"Variable '{name}' is assigned but never read."
                )

        # 5. Cyclomatic complexity
        for block in cc_visit(source):
            if block.complexity > 10:
                add_finding(
                    findings, "GAP006", "High cyclomatic complexity",
                    "MEDIUM", path, root, block.lineno,
                    f"'{block.name}' has complexity {block.complexity}."
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
        lines = source.splitlines()
        relative_path = str(path.relative_to(root))

        # 1. var declarations
        for match in re.finditer(r"\bvar\s+([a-zA-Z_$][\w$]*)", source):
            line = source.count("\n", 0, match.start()) + 1
            add_finding(
                findings, "GAP007", "Use of var declaration",
                "LOW", path, root, line,
                f"Variable '{match.group(1)}' uses var. Prefer let or const."
            )

        # 2. Loose equality
        for number, line in enumerate(lines, start=1):
            clean_line = re.sub(r"""(['"]).*?\1""", "", line)
            if re.search(r"(?<![=!])==(?![=])|!=(?!=)", clean_line):
                add_finding(
                    findings, "GAP008", "Loose equality comparison",
                    "LOW", path, root, number,
                    "Loose equality may cause unexpected type coercion. "
                    "Consider using === or !==."
                )

        # 3. Empty catch blocks
        for match in re.finditer(
            r"\bcatch\s*(?:\([^)]*\))?\s*\{\s*\}",
            source
        ):
            line = source.count("\n", 0, match.start()) + 1
            add_finding(
                findings, "GAP009", "Empty catch block",
                "MEDIUM", path, root, line,
                "Exceptions are caught but not handled or logged."
            )

        # 4. Too many function parameters
        function_patterns = [
            r"\bfunction\s*[\w$]*\s*\(([^)]*)\)",
            r"(?:const|let|var)\s+[\w$]+\s*=\s*(?:async\s*)?\(([^)]*)\)\s*=>",
        ]

        for pattern in function_patterns:
            for match in re.finditer(pattern, source):
                params = [
                    p.strip() for p in match.group(1).split(",")
                    if p.strip()
                ]

                if len(params) > 6:
                    line = source.count("\n", 0, match.start()) + 1
                    add_finding(
                        findings, "GAP010", "Too many function parameters",
                        "LOW", path, root, line,
                        f"Function has {len(params)} parameters."
                    )

        # 5. Potentially unused imports (simple heuristic)
        import_patterns = [
            r"\bimport\s+(\w+)\s+from\s+['\"][^'\"]+['\"]",
            r"\bimport\s+\{\s*([^}]+)\s*\}\s+from\s+['\"][^'\"]+['\"]",
        ]

        for pattern in import_patterns:
            for match in re.finditer(pattern, source):
                names = [
                    item.strip().split(" as ")[-1].strip()
                    for item in match.group(1).split(",")
                ]

                for name in names:
                    if not name or not re.match(r"^[\w$]+$", name):
                        continue

                    # Remove the import declaration before checking usage
                    remaining = source[:match.start()] + source[match.end():]

                    if not re.search(
                        rf"\b{re.escape(name)}\b", remaining
                    ):
                        line = source.count("\n", 0, match.start()) + 1
                        add_finding(
                            findings, "GAP011", "Potentially unused import",
                            "LOW", path, root, line,
                            f"Imported name '{name}' is not referenced."
                        )

        # 6. Potentially unused variables (basic heuristic)
        declaration_pattern = (
            r"\b(?:const|let|var)\s+([a-zA-Z_$][\w$]*)"
        )

        for match in re.finditer(declaration_pattern, source):
            name = match.group(1)
            remaining = source[:match.start()] + source[match.end():]

            if len(re.findall(rf"\b{re.escape(name)}\b", remaining)) == 0:
                line = source.count("\n", 0, match.start()) + 1
                add_finding(
                    findings, "GAP012", "Potentially unused variable",
                    "LOW", path, root, line,
                    f"Variable '{name}' is declared but never referenced."
                )

    except (UnicodeError, OSError, ValueError):
        pass

    return findings


# ---------------- REPOSITORY ANALYSIS ----------------

def analyze_coding_gaps(repo_path: str) -> dict:
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

        elif suffix in JS_EXTENSIONS:
            findings.extend(analyze_javascript_file(path, root))

    return {
        "category": "Coding Gaps",
        "total_findings": len(findings),
        "findings": findings
    }
