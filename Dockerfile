FROM commerceblock/base:a75da9a

COPY . /usr/src/package

# Build Ocean
RUN set -ex \
    && cd /usr/src/package \
    && ./autogen.sh \
    && ./configure --without-gui --with-curlpp=yes \
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
