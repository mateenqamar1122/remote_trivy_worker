import os
import shutil
import tempfile
import subprocess
import json
import logging
import multiprocessing
import signal
import asyncio
import time
from fastapi import FastAPI, HTTPException
from pydantic import BaseModel

app = FastAPI(title="Sentrige Remote Scanner")
logger = logging.getLogger("uvicorn.error")

class ScanRequest(BaseModel):
    repo_full_name: str
    token: str = ""
    provider: str = "github"

def get_opengrep_binary() -> str:
    for candidate in [
        shutil.which("opengrep"),
        "/root/.local/bin/opengrep",
        "/root/.opengrep/cli/latest/opengrep",
        "/usr/local/bin/opengrep"
    ]:
        if candidate and os.path.exists(candidate):
            return candidate
    return "opengrep"

def is_false_positive_secret(match: str, rule_id: str = "") -> bool:
    """
    Detects false positive secret occurrences:
    - Dynamic environment reads (e.g., Deno.env.get, process.env, os.environ, os.getenv)
    - Type annotations and interface signatures (e.g. apiKey: string)
    - Common placeholder and dummy test strings
    """
    if not match:
        return False
    m = match.strip().lower()

    # Dynamic environment variable access
    env_indicators = [
        "deno.env",
        "process.env",
        "os.environ",
        "os.getenv",
        "system.getenv",
        "env.get(",
        "getenv(",
        "config.get(",
        "settings.get(",
        "config[",
        "settings[",
        "secrets.get(",
        "request.headers",
        "req.headers",
        "headers.get",
    ]
    if any(ind in m for ind in env_indicators):
        return True

    # Type declarations
    type_indicators = [
        ": string",
        ": str",
        ": string |",
        ": optional[str]",
        ": text",
    ]
    if any(ind in m for ind in type_indicators):
        return True

    # Placeholders / mock tokens
    dummy_indicators = [
        "your_",
        "your-",
        "<your",
        "placeholder",
        "changeme",
        "dummy",
        "example",
        "xxxx",
        "test_key",
        "temp_key",
        "none",
        "null",
        "undefined",
        "true",
        "false",
        "123456",
        "sample",
    ]
    if any(ind in m for ind in dummy_indicators):
        return True

    # For generic secret rule, ensure it is an actual quoted string literal and not a function call
    if "generic" in rule_id.lower():
        if '"' not in match and "'" not in match and "`" not in match:
            return True
        if "(" in match and ")" in match:
            return True

    return False


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
            
        # Write Comprehensive Secret Rule Configuration for Trivy
        custom_secret_conf = os.path.join(repo_dir, "trivy-secret.yaml")
        with open(custom_secret_conf, "w") as f:
            f.write("""
rules:
  - id: aws-access-key-id
    category: AWS Access Key ID
    title: AWS Access Key ID
    severity: CRITICAL
    regex: '(?i)(?:A3T[A-Z0-9]|AKIA|AGPA|AIDA|AROA|AIPA|ANPA|ANVA|ASIA)[A-Z0-9]{16}'
  - id: aws-secret-access-key
    category: AWS Secret Access Key
    title: AWS Secret Access Key
    severity: CRITICAL
    regex: '(?i)(?:aws_secret_access_key|secretAccessKey|aws_secret_key)\\s*[:=]\\s*["''][A-Za-z0-9/+=]{16,}["'']'
  - id: supabase-publishable-key
    category: Supabase API Key
    title: Supabase API / JWT Token
    severity: HIGH
    regex: 'eyJ[A-Za-z0-9-_=]+\\.[A-Za-z0-9-_=]+\\.?[A-Za-z0-9-_.+/=]*'
  - id: generic-hardcoded-secret
    category: Generic Secret
    title: Generic Hardcoded Credentials
    severity: HIGH
    regex: '(?i)(?:access_key|secret_key|api_key|apikey|auth_token|passwd|password|private_key)\\s*[:=]\\s*["''][A-Za-z0-9_\\-/.+=]{16,}["'']'
  - id: gemini-api-key
    category: Google Gemini API Key
    title: Google Gemini API Key
    severity: CRITICAL
    regex: '(?i)AIza[0-9A-Za-z\\-_]{35}'
  - id: github-personal-access-token
    category: GitHub Personal Access Token
    title: GitHub Personal Access Token
    severity: CRITICAL
    regex: 'ghp_[a-zA-Z0-9]{36}|github_pat_[a-zA-Z0-9]{22}_[a-zA-Z0-9]{59}'
  - id: private-cryptographic-key
    category: Private Key
    title: Private Cryptographic Key
    severity: CRITICAL
    regex: '-----BEGIN (?:RSA|EC|OPENSSH|DSA|PRIVATE) KEY-----'
""")

        # Run Trivy with full scanners and comprehensive secret ruleset
        trivy_cmd = [
            "trivy", "fs", repo_dir,
            "--format", "json",
            "--quiet",
            "--scanners", "vuln,secret,misconfig,license",
            "--secret-config", custom_secret_conf
        ]

        # Write .opengrepignore and .semgrepignore to vastly speed up AST parsing on large codebases
        for ignore_file in [".opengrepignore", ".semgrepignore"]:
            ignore_path = os.path.join(repo_dir, ignore_file)
            with open(ignore_path, "w") as f:
                f.write("""
node_modules/
vendor/
packages/
.venv/
venv/
env/
dist/
build/
bin/
obj/
out/
.next/
.nuxt/
coverage/
*.exe
*.jar
*.min.js
*.css.map
*.bundle.js
*.chunk.js
                """.strip())

        cpu_count = multiprocessing.cpu_count()
        threads = str(max(1, min(4, cpu_count)))
        opengrep_bin = get_opengrep_binary()

        # Build OpenGrep command using local rules repository if available, plus standard packs
        opengrep_cmd = [opengrep_bin, "scan"]

        if os.path.exists("/opt/opengrep-rules") and os.path.isdir("/opt/opengrep-rules") and os.listdir("/opt/opengrep-rules"):
            opengrep_cmd.extend(["--config", "/opt/opengrep-rules"])
        else:
            opengrep_cmd.extend(["--config", "auto"])

        opengrep_cmd.extend([
            "-j", threads,
            "--timeout", "15",
            "--timeout-threshold", "3",
            "--max-target-bytes", "1000000",
            "--max-memory", "2048",
            "--skip-unknown-extensions",
            "--exclude", "node_modules/**",
            "--exclude", ".git/**",
            "--exclude", "vendor/**",
            "--json", "--quiet", "."
        ])

        logger.info(f"Executing Trivy and OpenGrep scanners concurrently on {req.repo_full_name} (OpenGrep threads: {threads})...")

        scan_env = os.environ.copy()
        # Clean any metrics / telemetry environment variables so OpenGrep does NOT receive unsupported '--metrics' flag
        for var in ["OPENGREP_SEND_METRICS", "SEMGREP_SEND_METRICS", "OPENGREP_ENABLE_VERSION_CHECK", "SEMGREP_ENABLE_VERSION_CHECK"]:
            scan_env.pop(var, None)
        scan_env["CI"] = "true"
        scan_env["TRIVY_NON_INTERACTIVE"] = "true"

        async def run_command(name, cmd):
            logger.info(f"[{name}] Starting execution with command: {' '.join(cmd[:4])}...")
            start_time = time.time()
            
            proc = await asyncio.create_subprocess_exec(
                *cmd,
                stdin=asyncio.subprocess.DEVNULL,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
                env=scan_env,
                cwd=repo_dir,
                preexec_fn=os.setsid if os.name == 'posix' else None
            )
            try:
                stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=600.0)
                elapsed = time.time() - start_time
                logger.info(f"[{name}] Finished successfully in {elapsed:.2f} seconds.")
            except asyncio.TimeoutError:
                if os.name == 'posix':
                    try:
                        os.killpg(os.getpgid(proc.pid), signal.SIGKILL)
                    except ProcessLookupError:
                        pass
                else:
                    proc.kill()
                    
                try:
                    stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=5.0)
                except asyncio.TimeoutError:
                    pass
                    
                elapsed = time.time() - start_time
                logger.error(f"[{name}] KILLED after {elapsed:.2f} seconds (Timeout reached).")
                return "", f"Process timed out after 600 seconds", -1
                
            return stdout.decode("utf-8", errors="ignore"), stderr.decode("utf-8", errors="ignore"), proc.returncode

        (trivy_out, trivy_err, trivy_code), (og_out, og_err, og_code) = await asyncio.gather(
            run_command("TRIVY", trivy_cmd),
            run_command("OPENGREP", opengrep_cmd)
        )

        results = {}

        # Parse Trivy Output
        trivy_str = trivy_out.strip()
        if not trivy_str:
            if "FATAL" in trivy_err:
                logger.error(f"Trivy fatal inner error: {trivy_err}")
            results["trivy"] = {"Results": []}
        else:
            try:
                parsed_trivy = json.loads(trivy_str)
                # Filter out false positive secrets (e.g. Deno.env.get, process.env, mock placeholders)
                for res in parsed_trivy.get("Results", []):
                    if "Secrets" in res and res["Secrets"]:
                        clean_secrets = []
                        for sec in res["Secrets"]:
                            match = sec.get("Match", "") or ""
                            rule_id = sec.get("RuleID", "")
                            if is_false_positive_secret(match, rule_id):
                                logger.info(f"[TRIVY] Dropped false positive secret in {res.get('Target')}: {match[:60]}")
                                continue
                            clean_secrets.append(sec)
                        res["Secrets"] = clean_secrets
                results["trivy"] = parsed_trivy
            except json.JSONDecodeError:
                logger.error(f"Failed to parse Trivy output: {trivy_err}")
                results["trivy"] = {"Results": []}

        # Parse OpenGrep Output
        og_str = og_out.strip()
        if og_err:
            logger.info(f"OpenGrep stderr: {og_err}")
            
        if not og_str:
            if og_err:
                logger.error(f"OpenGrep warning/error: {og_err}")
            results["opengrep"] = {"results": []}
        else:
            try:
                results["opengrep"] = json.loads(og_str)
            except json.JSONDecodeError:
                logger.error(f"Failed to parse OpenGrep output. Stderr: {og_err}")
                results["opengrep"] = {"results": []}

        return results

    finally:
        shutil.rmtree(work_dir, ignore_errors=True)

@app.get("/health")
def healthcheck():
    return {"status": "ok"}
