# (C) Copyright IBM Deutschland GmbH 2021, 2023
# (C) Copyright IBM Corp 2021, 2023
#
# non-exclusively licensed to gematik GmbH

########################################################################################################################

FROM de.icr.io/erp_dev/erp-pc-ubuntu-build:2.2.1 as prerequisites

RUN apt-get update --fix-missing && \
    apt-get install -y binutils

USER root
ARG CONAN_LOGIN_USERNAME
ARG CONAN_PASSWORD
ARG CONAN_URL

# setup Conan and add the Nexus Conan repository
#

RUN conan remote add erp-conan-2 ${CONAN_URL} && \
    conan remote auth erp-conan-2 && \
    conan list && \
    conan list -r erp-conan-2

########################################################################################################################

FROM prerequisites as build

# bring the sources
#
WORKDIR /source
COPY . .
COPY docker/files/default /root/.conan2/profiles/

# configure & build
#
SHELL ["/bin/bash", "-c"]
WORKDIR /build
RUN conan install /source --build=missing --output-folder=/build -pr:b=default -o '&:with_tests=True' -s build_type=Release
RUN cmake /source  -DCMAKE_TOOLCHAIN_FILE=/build/conan_toolchain.cmake -DCMAKE_POLICY_DEFAULT_CMP0091=NEW -DCMAKE_BUILD_TYPE=Release
RUN cmake --build .
RUN mkdir -p simulator/bin \
    && conan install -pr:b=default --requires=swtpm2/164-2020-192.1 --build=missing --generator VirtualRunEnv -o 'openssl/*:shared=False' -o 'openssl/*:no_zlib=True' \
    && source conanrun.sh \
    && cp `which tpm_server` simulator/bin

# clean up
#
RUN rm -rf $HOME/.conan \
           $HOME/.local

########################################################################################################################

FROM ubuntu:22.04 AS run

ARG DEBIAN_FRONTEND=noninteractive
RUN apt-get update --fix-missing && \
    apt-get install -y netcat && rm -rf /var/lib/apt/lists/*

# make a clean run directory
#
WORKDIR /run
RUN rm -rf *
COPY --from=build /build/simulator .
COPY --from=build /source/docker/entrypoint.sh /entrypoint.sh

CMD ["/entrypoint.sh"]

########################################################################################################################
