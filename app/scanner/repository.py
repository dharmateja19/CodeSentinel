
from pathlib import Path
from collections import Counter, defaultdict

from app.scanner.language_detector import detect_language


IGNORED_DIRS = {
    ".git", ".venv", "venv", "node_modules",
    "__pycache__", "dist", "build", ".next",
    "coverage", ".idea", ".vscode"
}

SENSITIVE_NAMES = {
    ".env", ".env.local", ".env.production",
    "id_rsa", "id_ed25519", "credentials.json"
}

MAX_FILE_SIZE = 1_000_000


def scan_repository(repo_path: str) -> dict:
    root = Path(repo_path).expanduser().resolve()

    if not root.exists() or not root.is_dir():
        raise ValueError("Invalid repository directory")

    files = []
    languages = Counter()
    language_files = defaultdict(list)

    total_lines = 0
    skipped_files = 0

    for file_path in root.rglob("*"):

        if any(part in IGNORED_DIRS for part in file_path.relative_to(root).parts):
            continue

        if file_path.is_symlink() or not file_path.is_file():
            continue

        if file_path.name.lower() in SENSITIVE_NAMES:
            skipped_files += 1
            continue

        language = detect_language(file_path)

        if language == "Unknown":
            continue

        try:
            size = file_path.stat().st_size

            if size > MAX_FILE_SIZE:
                skipped_files += 1
                continue

            content = file_path.read_text(
                encoding="utf-8",
                errors="replace"
            )

            line_count = len(content.splitlines())

            relative_path = file_path.relative_to(root).as_posix()

            file_info = {
                "path": relative_path,
                "language": language,
                "lines": line_count,
                "size": size
            }

            files.append(file_info)
            language_files[language].append(relative_path)

            languages[language] += 1
            total_lines += line_count

        except (OSError, ValueError):
            skipped_files += 1

    return {
        "repository": root.name,
        "total_files": len(files),
        "total_lines": total_lines,
        "skipped_files": skipped_files,
        "languages": dict(languages),
        "language_files": dict(language_files),
        "files": files
    }
