FROM python:3.11-slim AS builder

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

WORKDIR /app

RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates \
    git && \
    rm -rf /var/lib/apt/lists/*

COPY pyproject.toml README.md ./
COPY src/ src/
COPY .docker-sdk/ /tmp/agentfield-sdk/

RUN pip install --no-cache-dir --prefix=/install \
    /tmp/agentfield-sdk/ \
    "pydantic>=2.0" \
    "httpx>=0.27" \
    "python-dotenv>=1.0" \
    "pyhcl2>=2.0" && \
    pip install --no-cache-dir --prefix=/install --no-deps .


FROM python:3.11-slim AS runtime

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    AGENTFIELD_SERVER=http://agentfield:8080 \
    HARNESS_PROVIDER=opencode \
    HARNESS_MODEL=openrouter/moonshotai/kimi-k2.5 \
    AI_MODEL=openrouter/moonshotai/kimi-k2.5 \
    PORT=8005 \
    HOME=/home/cloudprove \
    PYTHONPATH=/app/src \
    PATH=/home/cloudprove/.opencode/bin:${PATH}

WORKDIR /app

RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates \
    curl \
    git && \
    groupadd --gid 10001 cloudprove && \
    useradd --uid 10001 --gid cloudprove --create-home --home-dir /home/cloudprove --shell /bin/sh cloudprove && \
    su -s /bin/sh cloudprove -c "curl -fsSL https://opencode.ai/install | bash" && \
    mkdir -p /workspaces && \
    chown -R cloudprove:cloudprove /app /workspaces /home/cloudprove && \
    rm -rf /var/lib/apt/lists/*

# Generate minimal opencode config for OpenRouter provider (no MCP servers)
RUN mkdir -p /home/cloudprove/.config/opencode && \
    echo '{"$schema":"https://opencode.ai/config.json","model":"openrouter/moonshotai/kimi-k2.5","small_model":"openrouter/moonshotai/kimi-k2.5","provider":{"openrouter":{"options":{"apiKey":"{env:OPENROUTER_API_KEY}"},"models":{"minimax/minimax-m2.5":{},"moonshotai/kimi-k2.5":{}}}}}' \
    > /home/cloudprove/.config/opencode/opencode.json && \
    chown -R cloudprove:cloudprove /home/cloudprove/.config

COPY --from=builder /install /usr/local
COPY src/ /app/src/
COPY prompts/ /app/prompts/

USER cloudprove

EXPOSE 8005

HEALTHCHECK --interval=30s --timeout=5s --retries=3 \
    CMD curl -f http://localhost:8005/health || exit 1

CMD ["python", "-m", "cloudprove_af.app"]
