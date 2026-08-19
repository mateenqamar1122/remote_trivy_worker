import os
import shutil
import tempfile
import subprocess
import json
from fastapi import FastAPI, HTTPException
from pydantic import BaseModel
import logging

app = FastAPI(title="Sentrige Remote Scanner")
logger = logging.getLogger("uvicorn.error")

class ScanRequest(BaseModel):
    repo_full_name: str
    token: str = ""

@app.post("/scan")
async def scan_repository(req: ScanRequest):
    work_dir = tempfile.mkdtemp(prefix="remote_trivy_")
    repo_dir = os.path.join(work_dir, "repo")
    
    try:
        # Clone repo
        if req.token:
            clone_url = f"https://x-access-token:{req.token}@github.com/{req.repo_full_name}.git"
        else:
            clone_url = f"https://github.com/{req.repo_full_name}.git"
            
        logger.info(f"Cloning {req.repo_full_name}...")
        clone_cmd = ["git", "clone", "--depth", "1", "--quiet", clone_url, repo_dir]
        clone_res = subprocess.run(clone_cmd, capture_output=True, encoding="utf-8")
        if clone_res.returncode != 0:
            raise HTTPException(status_code=400, detail=f"Git clone failed: {clone_res.stderr}")
            
        # Write Secret config
        custom_secret_conf = os.path.join(repo_dir, "trivy-secret.yaml")
        with open(custom_secret_conf, "w") as f:
            f.write("""
secrets:
  - id: gemini-api-key
    title: Google Gemini API Key
    severity: CRITICAL
    regex: >-
      (?i)AIza[0-9A-Za-z\\-_]{35}
  - id: generic-env-secret
    title: Generic Environment Secret
    severity: HIGH
    regex: >-
      (?i)(password|secret|token|api_key|apikey)\\s*[:=]\\s*[\"\']?[a-zA-Z0-9_\\-]{4,}[\"\']?
""")
            
        # Run Trivy
        trivy_cmd = [
            "trivy", "fs", repo_dir,
            "--format", "json",
            "--quiet",
            "--scanners", "vuln,secret,misconfig,license",
            "--secret-config", custom_secret_conf
        ]
        
        logger.info("Executing Trivy scanner...")
        # Note: We rely on Docker ENV GITHUB_TOKEN to prevent GHCR rate limiting
        res = subprocess.run(trivy_cmd, capture_output=True, encoding="utf-8", timeout=600)
        
        stdout_str = res.stdout.strip()
        if not stdout_str:
            if "FATAL" in res.stderr:
                logger.error(f"Trivy fatal inner error: {res.stderr}")
                raise HTTPException(status_code=500, detail=f"Trivy FATAL Error: {res.stderr[:500]}")
            return {"Results": []}
            
        try:
            return json.loads(stdout_str)
        except json.JSONDecodeError:
            raise HTTPException(status_code=500, detail=f"Failed to parse Trivy output. Error: {res.stderr}")
            
    finally:
        shutil.rmtree(work_dir, ignore_errors=True)

@app.get("/health")
def healthcheck():
    return {"status": "ok"}
