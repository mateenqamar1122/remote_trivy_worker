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
    provider: str = "github"

@app.post("/scan")
async def scan_repository(req: ScanRequest):
    work_dir = tempfile.mkdtemp(prefix="remote_trivy_")
    repo_dir = os.path.join(work_dir, "repo")
    
    try:
        # Clone repo
        if req.token:
            if req.provider == "gitlab":
                clone_url = f"https://oauth2:{req.token}@gitlab.com/{req.repo_full_name}.git"
            elif req.provider == "bitbucket":
                clone_url = f"https://x-token-auth:{req.token}@bitbucket.org/{req.repo_full_name}.git"
            else:
                clone_url = f"https://x-access-token:{req.token}@github.com/{req.repo_full_name}.git"
        else:
            if req.provider == "gitlab":
                clone_url = f"https://gitlab.com/{req.repo_full_name}.git"
            elif req.provider == "bitbucket":
                clone_url = f"https://bitbucket.org/{req.repo_full_name}.git"
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
            
        import asyncio

        # Run Trivy
        trivy_cmd = [
            "trivy", "fs", repo_dir,
            "--format", "json",
            "--quiet",
            "--scanners", "vuln,secret,misconfig,license",
            "--secret-config", custom_secret_conf
        ]
        
        # Run OpenGrep
        opengrep_cmd = [
            "/root/.opengrep/cli/latest/opengrep", "scan",
            "--config", "/opt/opengrep-rules",
            "--json", "--quiet", repo_dir
        ]
        
        logger.info("Executing Trivy and OpenGrep scanners concurrently...")
        
        async def run_command(cmd):
            proc = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            stdout, stderr = await proc.communicate()
            return stdout.decode("utf-8"), stderr.decode("utf-8"), proc.returncode

        (trivy_out, trivy_err, trivy_code), (og_out, og_err, og_code) = await asyncio.gather(
            run_command(trivy_cmd),
            run_command(opengrep_cmd)
        )

        results = {}

        # Parse Trivy
        trivy_str = trivy_out.strip()
        if not trivy_str:
            if "FATAL" in trivy_err:
                logger.error(f"Trivy fatal inner error: {trivy_err}")
            results["trivy"] = {"Results": []}
        else:
            try:
                results["trivy"] = json.loads(trivy_str)
            except json.JSONDecodeError:
                logger.error(f"Failed to parse Trivy output. Error: {trivy_err}")
                results["trivy"] = {"Results": []}

        # Parse OpenGrep
        og_str = og_out.strip()
        if not og_str:
            logger.error(f"OpenGrep error: {og_err}")
            results["opengrep"] = {"results": []}
        else:
            try:
                results["opengrep"] = json.loads(og_str)
            except json.JSONDecodeError:
                logger.error(f"Failed to parse OpenGrep output. Error: {og_err}")
                results["opengrep"] = {"results": []}

        return results
            
    finally:
        shutil.rmtree(work_dir, ignore_errors=True)

@app.get("/health")
def healthcheck():
    return {"status": "ok"}
