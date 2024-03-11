# Dockerfile
FROM ubuntu:latest

RUN apt-get update -y
RUN apt-get install -y curl
RUN curl --proto '=https' --tlsv1.2 -sSf -L https://install.determinate.systems/nix | sh -s -- install linux \
  --extra-conf "sandbox = false" \
  --init none \
  --no-confirm
ENV PATH="${PATH}:/nix/var/nix/profiles/default/bin"
RUN nix run nixpkgs#hello

RUN apt-get install -y \
    build-essential \
    git \
    make

RUN cd /tmp && \
    git clone https://github.com/ncopa/su-exec.git && \
    cd su-exec && \
    make && \
    cp -v ./su-exec /usr/bin && \
    chmod +s /usr/bin/su-exec && \
    rm -rf /tmp/su-exec
