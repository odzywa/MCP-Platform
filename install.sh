#!/bin/bash
set -e

GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
NC='\033[0m'

echo -e "${GREEN}"
echo "╔═══════════════════════════════════════╗"
echo "║       MCP Platform — Installer        ║"
echo "╚═══════════════════════════════════════╝"
echo -e "${NC}"

# Check Docker
if ! command -v docker &> /dev/null; then
  echo -e "${RED}Error: Docker is not installed.${NC}"
  echo "Install Docker: https://docs.docker.com/engine/install/"
  exit 1
fi

if ! docker compose version &> /dev/null; then
  echo -e "${RED}Error: Docker Compose v2 is not installed.${NC}"
  exit 1
fi

# Setup .env
if [ ! -f .env ]; then
  cp .env.example .env
  INSTALL_DIR=$(pwd)
  sed -i "s|MCP_HOST_DATA_PATH=.*|MCP_HOST_DATA_PATH=${INSTALL_DIR}/data|" .env
  echo -e "${YELLOW}Created .env with defaults. Edit it if needed.${NC}"
else
  echo ".env already exists, skipping."
fi

source .env

# Create data directories
mkdir -p data/configs
echo -e "${GREEN}✓ Data directories ready${NC}"

# Build runtime images first
echo ""
echo -e "${YELLOW}Building runtime images (this may take a few minutes)...${NC}"
docker compose --profile build-only build mcp-runtime-shell-image mcp-runtime-http-gateway-image
echo -e "${GREEN}✓ Runtime images built${NC}"

# Build and start platform
echo ""
echo -e "${YELLOW}Building and starting MCP Platform...${NC}"
docker compose build mcp-platform mcp-platform-operator
docker compose up -d mcp-platform mcp-platform-operator
echo -e "${GREEN}✓ Platform started${NC}"

# Wait for health
echo ""
echo -n "Waiting for platform to be ready"
for i in $(seq 1 30); do
  if curl -sf "http://localhost:${MCP_PLATFORM_PORT:-18100}/login" > /dev/null 2>&1; then
    echo ""
    echo -e "${GREEN}✓ Platform is up!${NC}"
    break
  fi
  echo -n "."
  sleep 2
done

echo ""
echo -e "${GREEN}═══════════════════════════════════════════${NC}"
echo -e "${GREEN}  MCP Platform is ready!${NC}"
echo -e "${GREEN}═══════════════════════════════════════════${NC}"
echo ""
echo -e "  UI:       ${YELLOW}http://localhost:${MCP_PLATFORM_PORT:-18100}${NC}"
echo -e "  Login:    ${YELLOW}admin / admin${NC}  (change after first login)"
echo ""
echo -e "  Docs:     ${YELLOW}docs/jak-stworzyc-mcp-server.md${NC}"
echo ""
