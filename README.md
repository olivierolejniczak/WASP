# WASP — Web Application Security Pentest Swarm

Patches and deployment configuration for running [Pentest-Swarm-AI](https://github.com/Armur-Ai/Pentest-Swarm-AI) **fully local, CPU-only** with [Ollama](https://ollama.com) and [OWASP Juice Shop](https://owasp.org/www-project-juice-shop/) as a built-in lab target.

---

## What's in this repo

Only the files we wrote. Drop them into a Pentest-Swarm-AI clone to apply the deployment.

```
cli/lab.go                   — patched lab runner (port 3002, reuse running container)
internal/tools/nuclei.go     — patched nuclei adapter (CPU-safe, non-TTY fix)
lab/docker-compose.yml       — OWASP Juice Shop on port 3002
README.md                    — this file
```

---

## How to apply

```bash
git clone https://github.com/Armur-Ai/Pentest-Swarm-AI.git
cd Pentest-Swarm-AI

# Drop in our patches
cp /path/to/WASP/cli/lab.go cli/lab.go
cp /path/to/WASP/internal/tools/nuclei.go internal/tools/nuclei.go

make build
sudo cp bin/pentestswarm /usr/local/bin/
```

---

## Infrastructure setup

### Ollama (CPU-only)

```bash
curl -fsSL https://ollama.com/install.sh | sh

# If port 11434 is taken, move Ollama to 11435
mkdir -p /etc/systemd/system/ollama.service.d/
echo -e '[Service]\nEnvironment="OLLAMA_HOST=0.0.0.0:11435"' \
  > /etc/systemd/system/ollama.service.d/override.conf
systemctl daemon-reload && systemctl restart ollama

ollama pull llama3.2:3b
```

### PostgreSQL + Redis

```bash
apt-get install -y postgresql redis-server
systemctl enable --now postgresql redis-server

sudo -u postgres psql -c "CREATE USER pentestswarm WITH PASSWORD 'pentestswarm';"
sudo -u postgres psql -c "CREATE DATABASE pentestswarm OWNER pentestswarm;"
```

### OWASP Juice Shop

```bash
cd lab/
docker compose up -d
# Juice Shop available at http://localhost:3002
```

### Security toolchain

```bash
# ProjectDiscovery tools
go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
go install github.com/projectdiscovery/httpx/cmd/httpx@latest
go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest
go install github.com/projectdiscovery/naabu/v2/cmd/naabu@latest
go install github.com/projectdiscovery/katana/cmd/katana@latest
go install github.com/projectdiscovery/dnsx/cmd/dnsx@latest
go install github.com/lc/gau/v2/cmd/gau@latest
go install github.com/ffuf/ffuf/v2@latest
go install github.com/sensepost/gowitness@latest
go install github.com/owasp-amass/amass/v4/...@latest
go install github.com/zricethezav/gitleaks/v8@latest

apt-get install -y nmap sqlmap gobuster
pip install semgrep --break-system-packages
curl -sSfL https://raw.githubusercontent.com/trufflesecurity/trufflehog/main/scripts/install.sh \
  | sh -s -- -b /usr/local/bin
```

### config.yaml

```yaml
orchestrator:
  provider: "ollama"
  model: "llama3.2:3b"
  endpoint: "http://localhost:11435"
  context_window: 8192
  max_tokens: 4096
  temperature: 0.1

database:
  host: "localhost"
  port: 5432
  user: "pentestswarm"
  password: "pentestswarm"
  name: "pentestswarm"
  sslmode: "disable"

redis:
  host: "localhost"
  port: 6379
  db: 0
```

---

## Run the lab

```bash
pentestswarm scan --lab --provider ollama --follow
```

The `--lab` flag detects the running Juice Shop on port 3002 and points the swarm at it automatically. No API key needed.

---

## What the patches fix

**`cli/lab.go`**
- Port changed 3000 → 3002 (3000 was occupied on this host)
- Added fast-path: detects an already-running Juice Shop and reuses it instead of spinning a new container every run

**`internal/tools/nuclei.go`**
- Fixes nuclei v3 hanging indefinitely in non-TTY contexts — it was blocking on an interactive cloud-auth prompt
- Switches from full template tree (triggers the hang) to focused subdirs: `exposures/`, `misconfiguration/`, `technologies/`, `vulnerabilities/`, `takeovers/`
- Adds `-duc` (disable update check), `-no-interactsh`, `-rl 30 -c 5` for CPU-only hosts

---

## Check system health

```bash
pentestswarm doctor
# Expected: 7/8 infra (API server is optional dashboard), 16/16 tools
```

---

## Legal

For authorized testing only. OWASP Juice Shop is an intentionally vulnerable app — safe and legal to scan locally.
