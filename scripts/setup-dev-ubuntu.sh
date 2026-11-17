#!/usr/bin/env bash
# One-time developer setup on Ubuntu (including WSL2): current stable Go and Docker Engine.
# Run as your normal user; it asks for your sudo password.
set -euo pipefail

# --- Go (latest stable from go.dev) -----------------------------------------
GO_VERSION=$(curl -fsSL 'https://go.dev/VERSION?m=text' | head -n1)   # e.g. go1.27.3
ARCH=$(dpkg --print-architecture)                                      # amd64 / arm64
echo "installing $GO_VERSION ($ARCH) into /usr/local/go…"
curl -fsSL "https://go.dev/dl/${GO_VERSION}.linux-${ARCH}.tar.gz" -o /tmp/go.tgz
sudo rm -rf /usr/local/go
sudo tar -C /usr/local -xzf /tmp/go.tgz
rm /tmp/go.tgz
if ! grep -q '/usr/local/go/bin' ~/.profile; then
  echo 'export PATH=$PATH:/usr/local/go/bin:$HOME/go/bin' >> ~/.profile
fi

# --- Docker Engine (official apt repository) ---------------------------------
if ! command -v docker >/dev/null; then
  echo "installing Docker Engine…"
  sudo apt-get update -y
  sudo apt-get install -y ca-certificates curl
  sudo install -m 0755 -d /etc/apt/keyrings
  sudo curl -fsSL https://download.docker.com/linux/ubuntu/gpg -o /etc/apt/keyrings/docker.asc
  sudo chmod a+r /etc/apt/keyrings/docker.asc
  . /etc/os-release
  echo "deb [arch=${ARCH} signed-by=/etc/apt/keyrings/docker.asc] https://download.docker.com/linux/ubuntu ${UBUNTU_CODENAME:-$VERSION_CODENAME} stable" \
    | sudo tee /etc/apt/sources.list.d/docker.list >/dev/null
  sudo apt-get update -y
  sudo apt-get install -y docker-ce docker-ce-cli containerd.io
fi
sudo usermod -aG docker "$USER"
sudo systemctl enable --now docker 2>/dev/null || sudo service docker start

echo
/usr/local/go/bin/go version
sudo docker version --format 'docker {{.Server.Version}}'
echo "done. Open a new Ubuntu shell (so the docker group and PATH apply), or run: newgrp docker"
