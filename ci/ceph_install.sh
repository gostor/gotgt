#!/bin/bash

set -e
set -x

sudo apt-get install -y python-virtualenv

# ceph-deploy and ceph

WORKDIR=$HOME/workdir
CEPH_RELEASE=jewel
mkdir $WORKDIR
pushd $WORKDIR

git clone -b "v2.0.0" --single-branch --depth 1 https://github.com/ceph/ceph-deploy
pushd ceph-deploy
./bootstrap
./ceph-deploy install --release ${CEPH_RELEASE} `hostname`
./ceph-deploy pkg --install librados-dev `hostname`
./ceph-deploy pkg --install librbd-dev `hostname`
./ceph-deploy pkg --install libcephfs-dev `hostname`
popd # ceph-deploy

popd # workdir
