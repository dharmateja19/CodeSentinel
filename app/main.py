
from fastapi import FastAPI, HTTPException
from pydantic import BaseModel
from app.scanner.repository import scan_repository
from app.analyzers.security import analyze_security
from app.analyzers.slop import analyze_slop
from app.analyzers.coding_gaps import analyze_coding_gaps
from app.analyzers.loose_ends import analyze_loose_ends
from app.agent.auditor import run_full_audit
from fastapi.middleware.cors import CORSMiddleware
from app.scanner.github import repository_context

app = FastAPI(
    title="CodeSentinel",
    description="Architecture-Agnostic AI Code Audit Agent",
    version="1.0.0"
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:5173"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

class ScanRequest(BaseModel):
    repo_path: str | None = None
    github_url: str | None = None

@app.get("/")
def home():
    return {
        "project": "CodeSentinel",
        "status": "running"
    }

@app.get("/health")
def health():
    return {"status": "healthy"}

@app.post("/api/scan")
def scan(request: ScanRequest):
    try:
        result = scan_repository(request.repo_path)
        return result

    except ValueError as error:
        raise HTTPException(
            status_code=400,
            detail=str(error)
        )

@app.post("/api/audit/security")
def security_audit(request: ScanRequest):
    try:
        return analyze_security(request.repo_path)

    except ValueError as error:
        raise HTTPException(
            status_code=400,
            detail=str(error)
        )
        
@app.post("/api/audit/slop")
def slop_audit(request: ScanRequest):
    try:
        return analyze_slop(request.repo_path)
    except ValueError as error:
        raise HTTPException(status_code=400, detail=str(error))
    
@app.post("/api/audit/coding-gaps")
def coding_gaps_audit(request: ScanRequest):
    try:
        return analyze_coding_gaps(request.repo_path)
    except ValueError as error:
        raise HTTPException(status_code=400, detail=str(error))
    
@app.post("/api/audit/loose-ends")
def loose_ends_audit(request: ScanRequest):
    try:
        return analyze_loose_ends(request.repo_path)
    except ValueError as error:
        raise HTTPException(status_code=400, detail=str(error))
    
@app.post("/api/audit")
def audit_repository(request: ScanRequest):
    with repository_context(
        repo_path=request.repo_path,
        github_url=request.github_url
    ) as root:
        return run_full_audit(str(root))
        
