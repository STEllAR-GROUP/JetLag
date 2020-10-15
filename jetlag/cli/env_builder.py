__license__ = """
Copyright (c) 2020 Karame (@kmoham6)

Distributed under the Boost Software License, Version 1.0. (See accompanying
file LICENSE_1_0.txt or copy at http://www.boost.org/LICENSE_1_0.txt)
"""

import argparse
import docker
import os

parser = argparse.ArgumentParser(description='build an environment.')
# set the linux dirtributions
distro = parser.add_mutually_exclusive_group()
distro.add_argument('-os', "--os",
                    choices=['ubuntu', 'fedora'],
                    default='fedora',
                    help='builds the image based on selected OS (default: frdora)'
                    )

# set the build type
parser.add_argument('-b', "--build",
                    choices=['debug', 'release'],
                    default='debug',
                    help='builds in "debug" or "release" mode (default: debug)'
                    )
parser.add_argument('-i', "--install",
                    choices=['debug', 'release'],
                    default='debug',
                    help="builds in 'debug' or 'release' mode (default: debug)"

                    )

# add user
parser.add_argument('-u', "--user",
                    choices=['stellar', 'karame'],
                    default='stellar',
                    help='adding user to the image build (default: stellar)'
                    )

# set the env
parser.add_argument("--env",
                    choices=['python', 'c++'],
                    help=' building the image based on python or c++ '
                    )
# set the build path
parser.add_argument('-p', "--path",
                    default='/home/stellar/git',
                    help='source directory'
                    )
# Choose the application
parser.add_argument('-app', "--app",
                    choices=['hpx', 'pybind11', 'blaze', 'blaze-tensor', 'blazemark'],
                    help=' Installing the applications.'
                    )
args = parser.parse_args()
package_manager = "dnf" if args.os == "fedora" else "apt"

fedora_dep = ["python3-pip", "sudo", "git",
              "boost-devel", "wget curl", "environment-modules", "findutils", "cmake", "gdb", "gcc-c++", "openmpi",
              "numpy", "bzip2-devel", "fontconfig-devel",
              "freetype-devel", "fribidi-devel", "harfbuzz-devel", "jansson-devel", "lame-devel", "lbzip2", "libass-devel",
              "libogg-devel", "libsamplerate-devel", "libtheora-devel", "libtool", "libvorbis-devel", "libxml2-devel",
              "libvpx-devel", "m4", "make", "meson", "nasm", "ninja-build", "numactl-devel", "opus-devel", "patch",
              "speex-devel", "tar", "xz-devel", "zlib-devel", "hwloc", "hwloc-devel","blas", "blas-devel", "lapack-devel",
              "pytest", "python3-devel"]

ubuntu_dep = ["autoconf", "automake", "sudo"
              "build-essential", "autopoint", "cmake", "git", "libass-dev", "libbz2-dev", "libfontconfig1-dev",
              "libfreetype6-dev", "libfribidi", "libharfbuzz-dev", "libjansson-dev", "liblzma-dev", "libmp3lame-dev",
              "libnuma-dev", "libogg-dev", "libopus-dev", "libsamplerate-dev", "libspeex-dev", "libtheora-dev",
              "libtool", "libtool-bin", "libvorbis-dev", "libx264-dev", "libxml2-dev", "libvpx-dev", "m4", "make",
              "nasm", "ninja-build", "patch", "pkg-config", "python", "tar", "zlib1g-dev", "meson", "python3-pip", 
              "hwloc", "hwloc-dev", "blas", "blas-dev", "lapack-dev", "pytest", "python3-dev"]
message = f"""
From {args.os} 
RUN {package_manager} -y update
RUN groupadd -r {args.user}
RUN useradd -r -m -g {args.user} -G wheel {args.user}
RUN echo '%wheel ALL=(ALL) NOPASSWD:ALL' >> /etc/sudoers
"""

if (args.os == 'ubuntu'):
    for i in ubuntu_dep:
        message += f"RUN {package_manager} install -y {i}\n"
else:

    for i in fedora_dep:
        message += f"RUN {package_manager} install -y {i}\n"
print(message)

# install hpx
if (args.app == 'hpx'):
    message += f"""
WORKDIR {args.path}
RUN git clone https://github.com/STEllAR-GROUP/hpx.git
WORKDIR {args.path}/hpx/build
RUN cmake \
    -DCMAKE_BUILD_TYPE={args.build}      \
    -DHPX_WITH_MALLOC=system             \
    -DHPX_WITH_MORE_THAN_64_THREADS=ON   \
    -DHPX_WITH_MAX_CPU_COUNT=80          \
    -DHPX_WITH_EXAMPLES=OFF              \
    {args.path}/hpx
RUN make -j install
"""

# install pybind11
if (args.app == 'pybind11'):
    message += f"""
WORKDIR {args.path}
RUN git clone https://github.com/pybind/pybind11.git
WORKDIR {args.path}/pybind11/build
RUN cmake \
        -DCMAKE_BUILD_TYPE={args.build}  \
        {args.path}/pybind11
RUN make -j install
"""

# install blaze and blazemark 
if (args.app == 'blaze' or args.app == 'blaze-tensor' or args.app == 'blazemark'):
    message += f"""
WORKDIR {args.path}
RUN git clone https://bitbucket.org/blaze-lib/blaze.git
WORKDIR {args.path}/blaze/build
RUN cmake \
    -DCMAKE_BUILD_TYPE={args.build}      \
    {args.path}/blaze   
RUN make -j install 
"""
#install blaze-tensor
if (args.app == 'blaze-tensor' or args.app == 'blazemark'):
    message += f"""
WORKDIR {args.path}
RUN git clone https://github.com/STEllAR-GROUP/blaze_tensor.git
WORKDIR {args.path}/blaze_tensor/build
RUN cmake \
     -DCMAKE_BUILD_TYPE={args.build}  \
     {args.path}/blaze_tensor
RUN make -j install 
"""

# write the message in a file called Dockerfile
with open("Dockerfile", 'w') as file:
    for line in message:
        file.write(line)

# build the dockerfile from above

docker_client = docker.from_env()

image_tag = "build"
image_name = "{image_name}:{tag}".format(
    image_name='dockerfile.python', tag=image_tag)
# #image_name = "dockerfile.python:build"
a = docker_client.images.build(
    path='/home/karame/repos/python-repo/', tag=image_name)


print(a)
