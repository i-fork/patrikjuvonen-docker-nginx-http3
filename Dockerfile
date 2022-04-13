##################################################
# Nginx with nginx-quic (HTTP/3), Brotli, Headers
# More and ModSec modules.
##################################################
# This is a fork of:
# ranadeeppolavarapu/docker-nginx-http3
#
# Differences in this fork:
# - BoringSSL OCSP enabled with kn007/patch
# - Removed nginx debug build
#
# Thanks to ranadeeppolavarapu/docker-nginx-http3
# for doing the ground work!
##################################################

FROM alpine:edge AS builder

LABEL maintainer="Patrik Juvonen <22572159+patrikjuvonen@users.noreply.github.com>"

ENV NGINX_VERSION 1.21.6
ENV MODSEC_TAG v3/master
ENV MODSEC_NGX_TAG master
ENV NJS_TAG 0.6.2

# Build-time metadata as defined at https://label-schema.org
ARG BUILD_DATE
ARG VCS_REF

# HACK: This patch is a temporary solution, might cause failures
COPY options.patch /usr/src/

RUN set -x \
  && CONFIG="\
  --prefix=/etc/nginx \
  --sbin-path=/usr/sbin/nginx \
  --modules-path=/usr/lib/nginx/modules \
  --conf-path=/etc/nginx/nginx.conf \
  --error-log-path=/var/log/nginx/error.log \
  --http-log-path=/var/log/nginx/access.log \
  --pid-path=/var/run/nginx.pid \
  --lock-path=/var/run/nginx.lock \
  --http-client-body-temp-path=/var/cache/nginx/client_temp \
  --http-proxy-temp-path=/var/cache/nginx/proxy_temp \
  --http-fastcgi-temp-path=/var/cache/nginx/fastcgi_temp \
  --http-uwsgi-temp-path=/var/cache/nginx/uwsgi_temp \
  --http-scgi-temp-path=/var/cache/nginx/scgi_temp \
  --user=nginx \
  --group=nginx \
  --with-pcre-jit \
  --with-http_ssl_module \
  --with-http_realip_module \
  --with-http_addition_module \
  --with-http_sub_module \
  --with-http_dav_module \
  --with-http_flv_module \
  --with-http_mp4_module \
  --with-http_gunzip_module \
  --with-http_gzip_static_module \
  --with-http_random_index_module \
  --with-http_secure_link_module \
  --with-http_stub_status_module \
  --with-http_auth_request_module \
  --with-http_xslt_module=dynamic \
  --with-http_image_filter_module=dynamic \
  --with-http_geoip_module=dynamic \
  --with-http_perl_module=dynamic \
  --with-threads \
  --with-stream \
  --with-stream_ssl_module \
  --with-stream_ssl_preread_module \
  --with-stream_realip_module \
  --with-stream_geoip_module=dynamic \
  --with-http_slice_module \
  --with-mail \
  --with-mail_ssl_module \
  --with-compat \
  --with-file-aio \
  --with-http_v2_module \
  --with-http_v2_hpack_enc \
  --with-http_v3_module \
  --with-stream_quic_module \
  --with-openssl=/usr/src/boringssl \
  --add-module=/usr/src/ngx_brotli \
  --add-module=/usr/src/headers-more-nginx-module \
  --add-module=/usr/src/njs/nginx \
  --add-module=/usr/src/nginx_cookie_flag_module \
  --add-module=/usr/src/ModSecurity-nginx \
  --with-cc-opt=-Wno-error \
  --with-select_module \
  --with-poll_module \
  " \
  && addgroup -S nginx \
  && adduser -D -S -h /var/cache/nginx -s /sbin/nologin -G nginx nginx \
  && apk update \
  && apk upgrade \
  && apk add --no-cache ca-certificates openssl \
  && update-ca-certificates \
  && apk add --no-cache --virtual .build-deps \
  gcc \
  libc-dev \
  make \
  pcre-dev \
  zlib-dev \
  linux-headers \
  gnupg \
  libxslt-dev \
  gd-dev \
  geoip-dev \
  perl-dev \
  && apk add --no-cache --virtual .brotli-build-deps \
  autoconf \
  libtool \
  automake \
  git \
  g++ \
  cmake \
  go \
  perl \
  rust \
  cargo \
  patch \
  && apk add --no-cache --virtual .nginx-quic-build-deps \
  mercurial \
  && apk add --no-cache --virtual .modsec-build-deps \
  libxml2-dev \
  byacc \
  flex \
  libstdc++ \
  libmaxminddb-dev \
  lmdb-dev \
  file \
  && cd /usr/src \
  && git clone --depth=1 --recursive --shallow-submodules https://github.com/google/boringssl \
  && cd boringssl \
  && mkdir build \
  && cd build \
  && cmake .. -DCMAKE_BUILD_TYPE=Release \
  && make -j$(getconf _NPROCESSORS_ONLN) \
  && cd .. \
  && mkdir build2 \
  && cd build2 \
  && cmake .. -DCMAKE_BUILD_TYPE=Release -DBUILD_SHARED_LIBS=1 \
  && make -j$(getconf _NPROCESSORS_ONLN) \
  && mkdir -p /usr/src/boringssl/.openssl/include/openssl \
  && cd /usr/src/boringssl/.openssl/include/openssl \
  && ln /usr/src/boringssl/include/openssl/* . \
  && mkdir /usr/src/boringssl/.openssl/lib \
  && cd /usr/src/boringssl/.openssl/lib \
  && cp /usr/src/boringssl/build/crypto/libcrypto.a . \
  && cp /usr/src/boringssl/build/ssl/libssl.a . \
  && cp /usr/src/boringssl/build2/crypto/libcrypto.so . \
  && cp /usr/src/boringssl/build2/ssl/libssl.so . \
  && cd /usr/src \
  && git clone --depth=1 --recursive --shallow-submodules https://github.com/google/ngx_brotli \
  && git clone --depth=1 --recursive --shallow-submodules https://github.com/openresty/headers-more-nginx-module \
  && git clone --branch $NJS_TAG --depth=1 --recursive --shallow-submodules https://github.com/nginx/njs \
  && git clone --depth=1 --recursive --shallow-submodules https://github.com/AirisX/nginx_cookie_flag_module \
  && curl -fSL https://raw.githubusercontent.com/QVQNetwork/ssl-patch/master/nginx-boringssl/0001-judgment-BoringSSL.patch -o 0001-judgment-BoringSSL.patch \
  && curl -fSL https://raw.githubusercontent.com/kn007/patch/cd03b77647c9bf7179acac0125151a0fbb4ac7c8/Enable_BoringSSL_OCSP.patch -o Enable_BoringSSL_OCSP.patch \
  && curl -fSL https://raw.githubusercontent.com/kn007/patch/f0b8ebd76924eb9c573c8056792b7f1d6f79d684/nginx.patch -o nginx.patch \
  && git clone --recursive --branch $MODSEC_TAG --single-branch https://github.com/SpiderLabs/ModSecurity \
  && git clone --depth=1 --recursive --shallow-submodules --branch $MODSEC_NGX_TAG --single-branch https://github.com/SpiderLabs/ModSecurity-nginx \
  && git clone --depth=1 --recursive --shallow-submodules https://github.com/coreruleset/coreruleset /usr/local/share/coreruleset \
  && CRS_COMMIT=$(git --git-dir=/usr/local/share/coreruleset/.git rev-parse --short HEAD) \
  && cp /usr/local/share/coreruleset/crs-setup.conf.example /usr/local/share/coreruleset/crs-setup.conf \
  && find /usr/local/share/coreruleset \! -name '*.conf' -type f -mindepth 1 -maxdepth 1 -delete \
  && find /usr/local/share/coreruleset \! -name 'rules' -type d -mindepth 1 -maxdepth 1 | xargs rm -rf \
  && cd /usr/src/ModSecurity \
  && ./build.sh \
  && ./configure --with-lmdb --enable-examples=no \
  && make -j$(getconf _NPROCESSORS_ONLN) \
  && make -j$(getconf _NPROCESSORS_ONLN) install \
  && cd /usr/src \
  && hg clone -b quic https://hg.nginx.org/nginx-quic \
  && mv nginx-quic nginx-$NGINX_VERSION \
  && cd /usr/src/nginx-$NGINX_VERSION \
  && NGINX_QUIC_REVISION=$(hg id -i) \
  && patch -p01 < /usr/src/nginx.patch || true \
  && patch -p01 < /usr/src/options.patch \
  && patch -p01 < /usr/src/0001-judgment-BoringSSL.patch \
  && patch -p01 < /usr/src/Enable_BoringSSL_OCSP.patch \
  && ./auto/configure $CONFIG \
    --with-cc-opt="-Wno-error -I/usr/src/boringssl/include" \
    --with-ld-opt="-L/usr/src/boringssl/build/ssl -L/usr/src/boringssl/build/crypto" \
    --build="docker-nginx-http3-$VCS_REF-$BUILD_DATE boringssl-$(git --git-dir=/usr/src/boringssl/.git rev-parse --short HEAD) nginx-quic-$NGINX_QUIC_REVISION ngx_brotli-$(git --git-dir=/usr/src/ngx_brotli/.git rev-parse --short HEAD) headers-more-nginx-module-$(git --git-dir=/usr/src/headers-more-nginx-module/.git rev-parse --short HEAD) njs-$(git --git-dir=/usr/src/njs/.git rev-parse --short HEAD) nginx_cookie_flag_module-$(git --git-dir=/usr/src/nginx_cookie_flag_module/.git rev-parse --short HEAD) ModSecurity-$(git --git-dir=/usr/src/ModSecurity/.git rev-parse --short HEAD) ModSecurity-nginx-$(git --git-dir=/usr/src/ModSecurity-nginx/.git rev-parse --short HEAD) coreruleset-$CRS_COMMIT" \
  && make -j$(getconf _NPROCESSORS_ONLN) \
  && make -j$(getconf _NPROCESSORS_ONLN) install \
  && rm -rf /etc/nginx/html/ \
  && mkdir /etc/nginx/conf.d/ \
  && mkdir /etc/nginx/modsec/ \
  # && mkdir -p /usr/share/nginx/html/ \
  # && install -m644 html/index.html /usr/share/nginx/html/ \
  # && install -m644 html/50x.html /usr/share/nginx/html/ \
  && install -m444 /usr/src/ModSecurity/modsecurity.conf-recommended /etc/nginx/modsec/modsecurity.conf \
  && install -m444 /usr/src/ModSecurity/unicode.mapping /etc/nginx/modsec/unicode.mapping \
  && ln -s /usr/lib/nginx/modules /etc/nginx/modules \
  && strip /usr/sbin/nginx* \
  && strip /usr/lib/nginx/modules/*.so \
  && strip /usr/local/modsecurity/bin/* \
  && strip /usr/local/modsecurity/lib/*.so.* \
  && strip /usr/local/modsecurity/lib/*.a \
  && rm -rf /etc/nginx/*.default /etc/nginx/*.so \
  && rm -rf /usr/src \
  \
  # Bring in gettext so we can get `envsubst`, then throw
  # the rest away. To do this, we need to install `gettext`
  # then move `envsubst` out of the way so `gettext` can
  # be deleted completely, then move `envsubst` back.
  && apk add --no-cache --virtual .gettext gettext \
  && mv /usr/bin/envsubst /tmp/ \
  \
  && runDeps="$( \
  scanelf --needed --nobanner /usr/sbin/nginx /usr/lib/nginx/modules/*.so /tmp/envsubst \
  | awk '{ gsub(/,/, "\nso:", $2); print "so:" $2 }' \
  | sort -u \
  | xargs -r apk info --installed \
  | sort -u \
  )" \
  && apk add --no-cache --virtual .nginx-rundeps $runDeps \
  && apk del .modsec-build-deps \
  && apk del .brotli-build-deps \
  && apk del .nginx-quic-build-deps \
  && apk del .build-deps \
  && apk del .gettext \
  && rm -rf /root/.cargo \
  && rm -rf /var/cache/apk/* \
  && mv /tmp/envsubst /usr/local/bin/ \
  # Create self-signed certificate
  && mkdir -p /etc/ssl/private \
  && openssl req -x509 -newkey rsa:4096 -nodes -keyout /etc/ssl/private/localhost.key -out /etc/ssl/localhost.pem -days 365 -sha256 -subj '/CN=localhost'

FROM alpine:edge

COPY --from=builder /usr/sbin/nginx /usr/sbin/
COPY --from=builder /usr/lib/nginx /usr/lib/nginx
# COPY --from=builder /usr/share/nginx/html/* /usr/share/nginx/html/
COPY --from=builder /etc/nginx/ /etc/nginx/
COPY --from=builder /usr/local/bin/envsubst /usr/local/bin/
COPY --from=builder /etc/ssl/private/localhost.key /etc/ssl/private/
COPY --from=builder /etc/ssl/localhost.pem /etc/ssl/
COPY --from=builder /usr/local/share/coreruleset /usr/local/share/coreruleset/
COPY --from=builder /usr/local/modsecurity /usr/local/modsecurity/

RUN \
  apk add --no-cache \
  # Bring in tzdata so users could set the timezones through the environment
  # variables
  tzdata \
  # Dependencies
  pcre \
  libgcc \
  libintl \
  # ModSecurity dependencies
  libxml2-dev \
  yajl-dev \
  geoip-dev \
  libstdc++ \
  libmaxminddb-dev \
  lmdb-dev \
  && addgroup -S nginx \
  && adduser -D -S -h /var/cache/nginx -s /sbin/nologin -G nginx nginx \
  # forward request and error logs to docker log collector
  && mkdir -p /var/log/nginx \
  && touch /var/log/nginx/access.log /var/log/nginx/error.log \
  && chown nginx: /var/log/nginx/access.log /var/log/nginx/error.log \
  && ln -sf /dev/stdout /var/log/nginx/access.log \
  && ln -sf /dev/stderr /var/log/nginx/error.log

COPY modsec/* /etc/nginx/modsec/

# Recommended nginx configuration. Please copy the config you wish to use.
# COPY nginx.conf /etc/nginx/
# COPY h3.nginx.conf /etc/nginx/conf.d/

STOPSIGNAL SIGTERM

CMD ["nginx", "-g", "daemon off;"]

LABEL org.label-schema.build-date=$BUILD_DATE \
  org.label-schema.vcs-ref=$VCS_REF \
  org.label-schema.vcs-url="https://github.com/patrikjuvonen/docker-nginx-http3.git"

EXPOSE 80 443 443/udp
