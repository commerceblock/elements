FROM ubuntu:18.04

ENV DEBIAN_FRONTEND=noninteractive
ENV TZ=UTC

RUN set -ex \
    && apt update && apt install -y software-properties-common \
    && add-apt-repository ppa:bitcoin/bitcoin \
    && apt update \
    && apt install -y build-essential make automake cmake curl g++-multilib libtool \
         binutils-gold bsdmainutils pkg-config python3 patch git golang-go \
         autoconf libtool pkg-config libboost-all-dev libssl-dev libprotobuf-dev protobuf-compiler \
         libevent-dev libqt4-dev libcanberra-gtk-module \
         libdb4.8-dev libdb4.8++-dev libcurl4-openssl-dev libcurlpp0 libcurlpp-dev \
    && git clone https://github.com/buildkite/github-release.git \
    && go get github.com/google/go-github/github \
    && go get github.com/oleiade/reflections \
    && go get golang.org/x/oauth2 \
    && git clone https://github.com/commerceblock/ocean.git \
    && rm -rf /var/lib/apt/lists/*
