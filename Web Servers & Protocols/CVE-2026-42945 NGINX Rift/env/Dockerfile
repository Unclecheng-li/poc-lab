FROM ubuntu:22.04
ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update && apt-get install -y \
    gcc make libpcre2-dev libssl-dev zlib1g-dev \
    util-linux python3 curl git \
    && rm -rf /var/lib/apt/lists/*

RUN git clone https://github.com/nginx/nginx.git /nginx-src \
    && cd /nginx-src && git checkout 98fc3bb78

RUN cd /nginx-src && ./auto/configure \
    --builddir=build \
    --with-cc-opt='-g -O2 -fno-omit-frame-pointer' \
    --with-ld-opt='-Wl,-z,relro -Wl,-z,now' \
    --with-http_ssl_module --with-http_v2_module \
    && make -j$(nproc)

WORKDIR /app
COPY nginx.conf server.py entrypoint.sh ./
RUN chmod +x entrypoint.sh && mkdir -p logs tmp

ENTRYPOINT ["/app/entrypoint.sh"]
EXPOSE 19321
