FROM commerceblock/debbase:latest

ARG token
ENV CURLPP_LIBS -L/usr/local/lib64 -lcurl -lcurlpp
ENV CURLPP_CFLAGS -Iinclude

RUN set -ex \
    && apt install -y jq libcurl4-openssl-dev \
    && export repo="repos/commerceblock/ocean/releases" \
    && export release_url="https://api.github.com/${repo}/latest" \
    && export id=$(curl -sH "Authorization: token ${token}" ${release_url} | jq .id) \
    && export tag_name=$(curl -sH "Authorization: token ${token}" ${release_url} | jq -r .tag_name) \
    && export upload_url="https://uploads.github.com/${repo}/${id}/assets?name=ocean-${tag_name}.deb" \
    && cd ocean \
    && git pull \
    && git checkout ${tag_name} \
    && ./autogen.sh \
    && ./configure --enable-glibc-back-compat \
        --prefix=`pwd`/depends/x86_64-pc-linux-gnu \
        LDFLAGS="-static-libstdc++" \
    && make -j$(nproc) \
    && mkdir -p ocean-${tag_name}/usr/local/bin \
    && cp src/oceand ocean-${tag_name}/usr/local/bin/ \
    && cp src/ocean-cli ocean-${tag_name}/usr/local/bin/ \
    && cp src/ocean-tx ocean-${tag_name}/usr/local/bin/ \
    && mkdir -p ocean-${tag_name}/DEBIAN \
    && cp contrib/docker/dpkg-build/control \
        ocean-${tag_name}/DEBIAN/ \
    && sed -i "s/Version: .*/Version: ${tag_name}/" \
        ocean-${tag_name}/DEBIAN/control \
    && dpkg-deb --build ocean-${tag_name} \
    && curl -v --data-binary @ocean-${tag_name}.deb \
       -H "Content-Type: multipart/form-data" \
       -H "Authorization: token $(echo $token)" \
       -H "Content-Type: application/octet-stream" \
       ${upload_url}
