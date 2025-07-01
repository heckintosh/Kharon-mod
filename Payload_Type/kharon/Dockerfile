FROM itsafeaturemythic/mythic_python_base:latest

RUN apt-get update && apt-get install -y python3 python3-pip clang build-essential apt-utils make python3-dev libboost-all-dev mingw-w64 nasm 

RUN python3 -m pip install mythic-container 

CMD ["python3", "Mythic/main.py"]