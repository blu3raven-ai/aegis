FROM python:3.13-slim

# Install Docker CLI for spawning scanner containers
RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates curl gnupg && \
    install -m 0755 -d /etc/apt/keyrings && \
    curl -fsSL https://download.docker.com/linux/debian/gpg -o /etc/apt/keyrings/docker.asc && \
    echo "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.asc] https://download.docker.com/linux/debian $(. /etc/os-release && echo "$VERSION_CODENAME") stable" > /etc/apt/sources.list.d/docker.list && \
    apt-get update && apt-get install -y --no-install-recommends docker-ce-cli docker-buildx-plugin && \
    rm -rf /var/lib/apt/lists/*

WORKDIR /app

COPY requirements.txt runner/requirements.txt
RUN pip install --no-cache-dir -r runner/requirements.txt

COPY . runner/

# Default: run as agent polling the backend
# Override with: docker run runner python -m runner.vuln_runner configure ...
ENV PYTHONUNBUFFERED=1
CMD ["python", "-c", "import logging, warnings; logging.basicConfig(level=logging.INFO, format='%(message)s'); logging.getLogger('httpx').setLevel(logging.WARNING); logging.getLogger('httpcore').setLevel(logging.WARNING); logging.getLogger('urllib3.connection').setLevel(logging.ERROR); warnings.filterwarnings('ignore', message='Failed to parse headers'); from runner.agent import RunnerAgent, load_config; a = RunnerAgent(load_config()); a.start()"]
