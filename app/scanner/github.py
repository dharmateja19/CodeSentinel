
import re
import subprocess
import tempfile

from contextlib import contextmanager
from pathlib import Path
from urllib.parse import urlsplit


def validate_github_url(url: str) -> str:
    if not isinstance(url, str) or not url.strip():
        raise ValueError("GitHub URL is required")

    url = url.strip()
    parsed = urlsplit(url)

    if (
        parsed.scheme != "https"
        or parsed.hostname != "github.com"
        or parsed.username
        or parsed.password
        or parsed.port not in (None, 443)
        or parsed.query
        or parsed.fragment
    ):
        raise ValueError("Only valid HTTPS GitHub repository URLs are supported")

    parts = parsed.path.strip("/").split("/")

    if len(parts) != 2:
        raise ValueError("Use a URL in the format https://github.com/owner/repository")

    owner, repository = parts

    if repository.endswith(".git"):
        repository = repository[:-4]

    valid_name = re.compile(r"^[A-Za-z0-9_.-]+$")

    if (
        not valid_name.fullmatch(owner)
        or not valid_name.fullmatch(repository)
        or owner in {".", ".."}
        or repository in {".", ".."}
    ):
        raise ValueError("Invalid GitHub owner or repository name")

    return f"https://github.com/{owner}/{repository}.git"


def clone_github_repository(url: str, destination: Path) -> None:
    validated_url = validate_github_url(url)

    try:
        subprocess.run(
            [
                "git",
                "clone",
                "--depth", "1",
                "--single-branch",
                "--no-tags",
                "--",
                validated_url,
                str(destination)
            ],
            check=True,
            capture_output=True,
            text=True,
            timeout=180
        )

    except FileNotFoundError:
        raise RuntimeError(
            "Git is not installed or is not available in PATH."
        )

    except subprocess.TimeoutExpired:
        raise RuntimeError(
            "Repository download timed out. Try a smaller repository."
        )

    except subprocess.CalledProcessError as error:
        message = error.stderr.strip() if error.stderr else ""

        if "Repository not found" in message:
            raise ValueError("Repository not found or is not public.")

        raise RuntimeError(
            f"Git clone failed: {message[:500] or 'Unknown Git error'}"
        )


@contextmanager
def repository_context(
    repo_path: str | None = None,
    github_url: str | None = None
):
    if bool(repo_path) == bool(github_url):
        raise ValueError(
            "Provide exactly one of repo_path or github_url."
        )

    if repo_path:
        root = Path(repo_path).expanduser().resolve()

        if not root.exists() or not root.is_dir():
            raise ValueError("Invalid repository directory")

        yield root
        return

    with tempfile.TemporaryDirectory(
        prefix="codesentinel_"
    ) as temporary_directory:

        destination = Path(temporary_directory) / "repository"

        clone_github_repository(
            github_url,
            destination
        )

        yield destination.resolve()
