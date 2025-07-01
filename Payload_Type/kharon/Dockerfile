FROM ubuntu:22.04

ENV DEBIAN_FRONTEND=noninteractive

# Install essential dependencies (including lsb-release)
RUN apt-get update && apt-get install -y --no-install-recommends \
    python3 \
    python3-pip \
    clang \
    build-essential \
    apt-utils \
    make \
    python3-dev \
    libboost-all-dev \
    mingw-w64 \
    nasm \
    git \
    wget \
    lsb-release \
    && rm -rf /var/lib/apt/lists/*

RUN wget https://apt.llvm.org/llvm.sh && chmod +x llvm.sh && ./llvm.sh 16

RUN python3 -m pip install mythic-container

RUN mkdir -p /Mythic
COPY . /Mythic/

WORKDIR /Mythic/Mythic

CMD ["python3", "main.py"]