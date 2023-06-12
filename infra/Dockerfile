ARG PYCA_RELEASE

FROM quay.io/pypa/${PYCA_RELEASE}
MAINTAINER Tongsuo Project Authors
ARG PYCA_RELEASE
ARG TONGSUO_HOME
ARG TONGSUO_VERSION
ENV TONGSUO_HOME=${TONGSUO_HOME}
ENV TONGSUO_VERSION=${TONGSUO_VERSION}
WORKDIR /root
RUN \
  if [ $(uname -m) = "x86_64" ]; \
  then \
    if stat /etc/redhat-release 1>&2 2>/dev/null; then \
      yum -y install wget binutils perl-IPC-Cmd && \
      yum -y clean all && \
      rm -rf /var/cache/yum; \
    elif stat /etc/debian_version 1>&2 2>/dev/null; then \
      export DEBIAN_FRONTEND=noninteractive && \
      sed -i s/deb.debian.org/archive.debian.org/g /etc/apt/sources.list && \
      sed -i 's|security.debian.org|archive.debian.org/|g' /etc/apt/sources.list && \
      sed -i '/stretch-updates/d' /etc/apt/sources.list && \
      apt-get update -qq && \
      apt-get install -qq -y --no-install-recommends wget prelink && \
      apt-get clean -qq && \
      rm -rf /var/lib/apt/lists/*; \
    else \
      echo "This is alpine and we don't need any more packages"; \
    fi; \
  fi

# This is done as two separate steps because readelf (binutils) is not available on
# aarch64, and libffi-dev/devel isn't required on x86_64 (since wheels exist)
RUN \
  if [ $(uname -m) = "aarch64" ]; \
  then \
    if stat /etc/redhat-release 1>&2 2>/dev/null; then \
      yum -y install libffi-devel perl-IPC-Cmd wget && \
      yum -y clean all && \
      rm -rf /var/cache/yum; \
    elif stat /etc/debian_version 1>&2 2>/dev/null; then \
      export DEBIAN_FRONTEND=noninteractive && \
      sed -i s/deb.debian.org/archive.debian.org/g /etc/apt/sources.list && \
      sed -i 's|security.debian.org|archive.debian.org/|g' /etc/apt/sources.list && \
      sed -i '/stretch-updates/d' /etc/apt/sources.list && \
      apt-get update -qq && \
      apt-get install -qq -y --no-install-recommends libffi-dev wget prelink && \
      apt-get clean -qq && \
      rm -rf /var/lib/apt/lists/*; \
    else \
      # musllinux_1_1 ships with gcompat 0.4 which is too old. Commit computer crimes
      # by adding a newer gcompat to an old alpine so that our GH actions will work.
      # Your laptop is not waterproof so please turn away lest your tears damage it.
      echo "http://dl-cdn.alpinelinux.org/alpine/v3.17/main" >> /etc/apk/repositories && \
      echo "http://dl-cdn.alpinelinux.org/alpine/v3.17/community" >> /etc/apk/repositories && \
      apk add --no-cache gcompat; \
    fi; \
  fi

# build tongsuo
RUN set -ex && \
    wget "https://github.com/Tongsuo-Project/Tongsuo/archive/refs/tags/${TONGSUO_VERSION}.tar.gz" && \
    tar zxf "${TONGSUO_VERSION}.tar.gz"

RUN set -ex && \
    cd "Tongsuo-${TONGSUO_VERSION}" && \
    ./config no-shared enable-ntls --release --prefix=${TONGSUO_HOME} && \
    make -s -j4 && \
    make install_sw
