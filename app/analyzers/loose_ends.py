
import ast
import re
from pathlib import Path

IGNORED_DIRS = {
    ".git", "venv", ".venv", "node_modules",
    "__pycache__", "dist", "build"
}

SOURCE_EXTENSIONS = {
    ".py", ".js", ".jsx", ".ts", ".tsx",
    ".java", ".cpp", ".cc", ".c", ".h",
    ".hpp", ".go", ".rs", ".php", ".rb",
    ".cs", ".swift", ".kt", ".sql", ".sh"
}

TODO_PATTERN = re.compile(
    r"\b(TODO|FIXME|XXX|HACK|BUG)\b",
    re.IGNORECASE
)

# JavaScript / TypeScript placeholder patterns
JS_PLACEHOLDER_PATTERNS = [
    (
        "END004",
        "Unimplemented function",
        r"\bthrow\s+new\s+Error\s*\(\s*['\"]Not implemented['\"]\s*\)"
    ),
    (
        "END005",
        "Empty function implementation",
        r"\bfunction\s+[\w$]+\s*\([^)]*\)\s*\{\s*\}"
    ),
    (
        "END005",
        "Empty arrow function",
        r"(?:=\s*|\(\s*\)\s*=>\s*)\([^)]*\)\s*=>\s*\{\s*\}"
    ),
]


def analyze_python(path: Path, root: Path) -> list:
    findings = []

    try:
        source = path.read_text(encoding="utf-8", errors="replace")
        tree = ast.parse(source)

        for node in ast.walk(tree):

            if isinstance(node, ast.Raise):
                if isinstance(node.exc, ast.Call):
                    func = node.exc.func

                    if (
                        isinstance(func, ast.Name)
                        and func.id == "NotImplementedError"
                    ):
                        findings.append({
                            "id": "END001",
                            "title": "Unimplemented functionality",
                            "severity": "MEDIUM",
                            "file": str(path.relative_to(root)),
                            "line": node.lineno,
                            "description": (
                                "Function explicitly raises NotImplementedError."
                            )
                        })

            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                meaningful = [
                    item for item in node.body
                    if not (
                        isinstance(item, ast.Expr)
                        and isinstance(item.value, ast.Constant)
                        and isinstance(item.value.value, str)
                    )
                ]

                is_pass = (
                    len(meaningful) == 1
                    and isinstance(meaningful[0], ast.Pass)
                )

                is_ellipsis = (
                    len(meaningful) == 1
                    and isinstance(meaningful[0], ast.Expr)
                    and isinstance(meaningful[0].value, ast.Constant)
                    and meaningful[0].value.value is Ellipsis
                )

                if is_pass or is_ellipsis:
                    findings.append({
                        "id": "END002",
                        "title": "Empty function implementation",
                        "severity": "MEDIUM",
                        "file": str(path.relative_to(root)),
                        "line": node.lineno,
                        "description": (
                            f"Function '{node.name}' contains only "
                            f"{'pass' if is_pass else 'an ellipsis placeholder'}."
                        )
                    })

    except (SyntaxError, UnicodeError, OSError, ValueError):
        pass

    return findings


def analyze_javascript(path: Path, root: Path) -> list:
    findings = []

    try:
        source = path.read_text(encoding="utf-8", errors="replace")
        relative_path = str(path.relative_to(root))

        for rule_id, title, pattern in JS_PLACEHOLDER_PATTERNS:
            for match in re.finditer(pattern, source):
                line = source.count("\n", 0, match.start()) + 1

                findings.append({
                    "id": rule_id,
                    "title": title,
                    "severity": "MEDIUM",
                    "file": relative_path,
                    "line": line,
                    "description": (
                        "Potential unfinished JavaScript/TypeScript "
                        "function implementation."
                    )
                })

    except (OSError, UnicodeError, ValueError):
        pass

    return findings


def analyze_loose_ends(repo_path: str) -> dict:
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

        if path.suffix.lower() not in SOURCE_EXTENSIONS:
            continue

        try:
            if path.stat().st_size > 1_000_000:
                continue

            lines = path.read_text(
                encoding="utf-8",
                errors="replace"
            ).splitlines()

            for number, line in enumerate(lines, start=1):
                match = TODO_PATTERN.search(line)

                if match:
                    findings.append({
                        "id": "END003",
                        "title": f"{match.group(1).upper()} comment",
                        "severity": "LOW",
                        "file": str(path.relative_to(root)),
                        "line": number,
                        "description": (
                            "Unresolved development task or warning marker."
                        )
                    })

            suffix = path.suffix.lower()

            if suffix == ".py":
                findings.extend(analyze_python(path, root))

            elif suffix in {".js", ".jsx", ".ts", ".tsx"}:
                findings.extend(analyze_javascript(path, root))

        except (OSError, ValueError):
            continue

    return {
        "category": "Loose Ends",
        "total_findings": len(findings),
        "findings": findings
    }
