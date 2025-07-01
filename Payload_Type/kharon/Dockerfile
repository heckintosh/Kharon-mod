FROM itsafeaturemythic/mythic_python_base:latest

RUN apt-get update && apt-get install python3 python3-pip \ 
    python3.11-venv -y clang* build-essential apt-utils   \
    cmake libfontconfig1 libglu1-mesa-dev libgtest-dev    \
    libspdlog-dev libboost-all-dev libncurses5-dev libgdbm-dev \
    libssl-dev libreadline-dev libffi-dev libsqlite3-dev libbz2-dev \
    python3-dev libboost-all-dev mingw-w64 nasm

WORKDIR /Mythic/
RUN python3 -m venv /venv
RUN /venv/bin/python -m pip install mythic-container collections struct logging os binascii base64 json

WORKDIR /Mythic/

CMD ["python3", "main.py"]