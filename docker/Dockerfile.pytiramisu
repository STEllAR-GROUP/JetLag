# Copyright (c) 2020 R. Tohid (@rtohid)
#
# Distributed under the Boost Software License, Version 1.0. (See a copy at
# http://www.boost.org/LICENSE_1_0.txt)

FROM ubuntu:18.04

RUN apt update
RUN apt install -y sudo

# OS Packages
RUN apt install -y python3.8 python3.8-dev python3.8-distutils
RUN apt install -y build-essential
RUN apt install -y cmake automake autoconf libtool lld
RUN apt install -y libpng-dev libjpeg-dev
RUN apt install -y zlib1g-dev libz-dev
RUN apt install -y git vim
RUN apt install -y wget curl
RUN apt install -y bash-completion
RUN apt install -y llvm-8 llvm-8-dev clang-8

WORKDIR /tmp/
RUN curl https://bootstrap.pypa.io/get-pip.py -o get-pip.py
RUN CC=clang-8 CXX=clang++-8 python3.8 get-pip.py
RUN CC=clang-8 CXX=clang++-8 python3.8 -m pip install pytest pylint yapf
RUN CC=clang-8 CXX=clang++-8 python3.8 -m pip install astpretty
RUN CC=clang-8 CXX=clang++-8 python3.8 -m pip install pybind11
RUN CC=clang-8 CXX=clang++-8 python3.8 -m pip install numpy
RUN CC=clang-8 CXX=clang++-8 python3.8 -m pip install jupyter

# ## MPI
# RUN apt install -y openmpi-bin openmpi-common libopenmpi-dev # libopenmpi-dbg
# RUN apt install -y openssh-client openssh-server


WORKDIR /home/stellar/git
RUN git clone -b physl_2019 --single-branch https://github.com/ct-clmsn/tiramisu.git

# ISL
WORKDIR /home/stellar/git/tiramisu/3rdParty/isl/build
WORKDIR /home/stellar/git/tiramisu/3rdParty/isl/

RUN CC=clang-8 CXX=clang++-8 ./configure --prefix=$PWD/build/ --with-int=imath
RUN CC=clang-8 CXX=clang++-8 make -j
RUN CC=clang-8 CXX=clang++-8 make install


RUN adduser --disabled-password --gecos '' stellar
RUN adduser stellar sudo
RUN echo '%sudo ALL=(ALL) NOPASSWD:ALL' >> /etc/sudoers

WORKDIR /home/stellar/git/tiramisu/
RUN sed -i 's/llvm-config/llvm-config-8/g' CMakeLists.txt
RUN sed -i 's/clang++/clang++-8/g' CMakeLists.txt

WORKDIR /home/stellar/git/tiramisu/build
RUN cmake -DUSE_HALIDE=OFF -DCMAKE_C_COMPILER=clang-8 -DCMAKE_CXX_COMPILER=clang++-8 ..
RUN make -j tiramisu

WORKDIR /home/stellar/git
RUN git clone -b backend --single-branch https://github.com/ct-clmsn/phyflow.git

WORKDIR /home/stellar/git/phyflow/backend
RUN ln -s /home/stellar/git/tiramisu/build/libtiramisu.so .
RUN HOME=/home/stellar make CXX=clang++-8 ISL_ROOT_DIR=/home/stellar/git/tiramisu/3rdParty/isl/ ISL_LIB_DIR=/home/stellar/git/tiramisu/3rdParty/isl/build/lib

WORKDIR /home/stellar/git
RUN git clone https://github.com/STEllAR-GROUP/phyfleaux.git

RUN chown -R stellar:stellar /home/stellar


WORKDIR /home/stellar
USER stellar

WORKDIR /tmp/
RUN sh -c "$(wget https://raw.githubusercontent.com/ohmybash/oh-my-bash/master/tools/install.sh -O -)"
RUN echo "export LD_LIBRARY_PATH=\$LD_LIBRARY_PATH:/home/stellar/git/phyflow/backend" >> /home/stellar/.bashrc
RUN echo "export PYTHONPATH=/home/stellar/git/phyflow/backend" >> /home/stellar/.bashrc
RUN echo "export PYTHONPATH=#PYTHONPATH:/home/stellar/git/phyfleaux/" >> /home/stellar/.bashrc

WORKDIR /home/stellar/
