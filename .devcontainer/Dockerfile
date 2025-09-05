FROM ubuntu:24.04

ARG LANG=en_US.UTF-8
ARG LANGUAGE=en_US.UTF-8
ARG LC_ALL=en_US.UTF-8

RUN echo "updating packages of base image" \
    && export DEBIAN_FRONTEND=noninteractive \
    && apt-get update \
    && apt-get -y dist-upgrade \
    && apt-get install -y locales \
    && sed -i '/'${LANG}'/s/^# //g' /etc/locale.gen \
    && locale-gen \
    && unset DEBIAN_FRONTEND

ENV LANG=${LANG}
ENV LANGUAGE=${LANGUAGE}
ENV LC_ALL=${LC_ALL}

RUN echo "installing essential devtools" \
    && export DEBIAN_FRONTEND=noninteractive \
    && apt-get -y install \
        apt-transport-https \
        ca-certificates \
        ccache \
        curl \
        fzf \
        git \
        jq \
        less \
        ninja-build \
        pipx \
        procps \
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
        zsh \
    && unset DEBIAN_FRONTEND

RUN echo "installing Botan-specific tools and dependencies" \
    && export DEBIAN_FRONTEND=noninteractive \
    && apt-get -y install \
        clang \
        clang-format-17 \
        clangd-20 \
        doxygen \
        gdb \
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
        ruff \
    && unset DEBIAN_FRONTEND

ENTRYPOINT ["/usr/local/bin/docker-entrypoint"]
