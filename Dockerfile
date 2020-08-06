FROM debian:buster

# common packages

RUN apt-get update && apt-get install --no-install-recommends -y \
  ca-certificates curl file libgmp-dev \
  build-essential \
  autoconf automake autotools-dev libtool xutils-dev && \
  rm -rf /var/lib/apt/lists/*

ENV SSL_VERSION=1.0.2s

RUN curl https://www.openssl.org/source/openssl-$SSL_VERSION.tar.gz -O && \
  tar -xzf openssl-$SSL_VERSION.tar.gz && \
  cd openssl-$SSL_VERSION && ./config && make depend && make install && \
  cd .. && rm -rf openssl-$SSL_VERSION*

ENV OPENSSL_LIB_DIR=/usr/local/ssl/lib \
  OPENSSL_INCLUDE_DIR=/usr/local/ssl/include \
  OPENSSL_STATIC=1

RUN curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- --default-toolchain nightly -y
ENV PATH=/root/.cargo/bin:$PATH
RUN rustup default nightly

RUN mkdir /app
WORKDIR /app

COPY . .

RUN cargo build --release

CMD ["./target/release/tss_cli", "manager"]
