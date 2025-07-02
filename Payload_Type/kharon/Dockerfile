FROM ubuntu:24.04

ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update && apt-get install -y --no-install-recommends \
    python3 \
    python3-pip \
    build-essential \
    apt-utils \
    clang \
    make \
    python3-dev \
    mingw-w64 \
    nasm \
    git \
    wget \
    lsb-release \
    software-properties-common \
    gnupg \
    && rm -rf /var/lib/apt/lists/*

RUN wget https://apt.llvm.org/llvm.sh \
    && chmod +x llvm.sh \
    && ./llvm.sh \
    && rm llvm.sh

RUN python3 -m pip install mythic-container --break-system-packages

RUN mkdir -p /Mythic
COPY . /Mythic/

WORKDIR /Mythic/Mythic

CMD ["python3", "main.py"]