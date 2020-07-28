FROM commerceblock/base:1142fc1

COPY . /usr/src/package

# Build Ocean
RUN set -ex \
    && git clone --branch v0.8.1 https://github.com/jpbarrette/curlpp.git \
    && cd curlpp \
    && mkdir build \
    && cd build \
    && cmake .. \
    && make \
    && make install \
    && export CURLPP_LIBS=`curlpp-config --libs` \
    && export CURLPP_CFLAGS=`curlpp-config --cflags` \
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
