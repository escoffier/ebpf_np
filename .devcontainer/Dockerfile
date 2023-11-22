FROM mcr.microsoft.com/devcontainers/go:dev-1.21-bullseye

RUN apt-get -y update \
  && apt-get -y install --no-install-recommends \
  git \
  clang \
  clangd \
  llvm \
  libbpf-dev \
  libelf-dev \
  libpcap-dev \
  iproute2 2>&1 \
  # linux-headers-5.15.49-linux 2>&1 \
  && apt-get clean \
  && rm -rf /var/lib/apt/lists/*p