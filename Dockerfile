FROM commerceblock/base:1142fc1

COPY . /usr/src/package

# Build Ocean
RUN set -ex \
    && yum -y install wget \
    && wget https://github.com/jpbarrette/curlpp/archive/v0.8.1.tar.gz \
    && echo "97e3819bdcffc3e4047b6ac57ca14e04af85380bd93afe314bee9dd5c7f46a0a v0.8.1.tar.gz" | sha256sum -c \
    && tar xvfz v0.8.1.tar.gz \
    && cd curlpp-0.8.1 \
    && mkdir build \
    && cd build \
    && cmake .. \
    && make \
    && make install \
    && export CURLPP_LIBS=`curlpp-config --libs` \
    && export CURLPP_CFLAGS=`curlpp-config --cflags` \
    && export LD_LIBRARY_PATH=/usr/local/lib64 \
    && cd /usr/src/package \
    && ./autogen.sh \
    && ./configure --without-gui \
    && make clean \
    && make -j$(nproc) \
    && echo "Running tests" \
    && make check \
    && echo "Running Python QA tests" \
    && ./qa/pull-tester/rpc-tests.py \
    && make install \
    && make clean \
    && cd /usr/src \
    && mkdir -p /home/bitcoin/.bitcoin \
    && cp -R package/doc/terms-and-conditions /home/bitcoin/.bitcoin \
    && chown -R bitcoin:bitcoin /home/bitcoin \
    && rm -rf package

COPY contrib/docker/docker-entrypoint.sh /docker-entrypoint.sh

ENTRYPOINT ["/docker-entrypoint.sh"]
CMD ["oceand"]
