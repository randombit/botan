FROM ubuntu:24.04

ARG LANG=en_US.UTF-8
ARG LANGUAGE=en_US.UTF-8
ARG LC_ALL=en_US.UTF-8

RUN echo "unminimize the ubuntu base image" \
    && yes | unminimize

RUN echo "updating packages of base image" \
    && apt-get update \
    && apt-get -y dist-upgrade \
    && DEBIAN_FRONTEND=noninteractive apt-get install -y locales \
    && sed -i '/'${LANG}'/s/^# //g' /etc/locale.gen \
    && locale-gen

ENV LANG=${LANG}
ENV LANGUAGE=${LANGUAGE}
ENV LC_ALL=${LC_ALL}

RUN echo "installing essential devtools" \
    && DEBIAN_FRONTEND=noninteractive apt-get -y --no-install-recommends install \
        apt-transport-https \
        build-essential \
        ca-certificates \
        ccache \
        clang \
        clang-format-17 \
        clangd-20 \
        curl \
        fzf \
        gdb \
        git \
        jq \
        less \
        ninja-build \
        pipx \
        procps \
        pylint \
        python3-pip \
        python3.12 \
        shellcheck \
        software-properties-common \
        sudo \
        tig \
        unzip \
        valgrind \
        vim \
        wget \
        zsh

RUN echo "installing Botan-specific tools and dependencies" \
    && DEBIAN_FRONTEND=noninteractive apt-get -y --no-install-recommends install \
        doxygen \
        golang \
        libboost-dev \
        libtss2-tcti-tabrmd0 \
        python3-docutils \
        python3-sphinx \
        softhsm2 \
        swtpm \
        swtpm-tools \
        tpm2-abrmd \
        tpm2-tools \
    && apt-get autoremove --purge \
    && rm -fR /var/cache/apt/archives \
    && pipx install \
        ruff

ENTRYPOINT ["/usr/local/bin/docker-entrypoint"]
