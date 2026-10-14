# (C) Copyright IBM Deutschland GmbH 2021, 2023
# (C) Copyright IBM Corp 2021, 2023
#
# non-exclusively licensed to gematik GmbH

########################################################################################################################

FROM conanio/gcc10:1.59.0 AS prerequisites

USER root
ARG NEXUS_USERNAME
ARG NEXUS_PASSWORD

# setup Conan and add the Nexus Conan repository
#
RUN conan config init --force &&                                                    \
    conan profile new default --detect --force &&                                   \
    conan profile update settings.build_type=Release default &&                     \
    conan profile update settings.compiler.libcxx=libstdc++11 default &&            \
    conan remote add erp https://nexus.epa-dev.net/repository/erp-conan-internal && \
    conan user $NEXUS_USERNAME -r erp -p $NEXUS_PASSWORD

########################################################################################################################

FROM prerequisites as build

# bring the sources
#
WORKDIR /source
COPY . .

# configure & build
#
SHELL ["/bin/bash", "-c"]
WORKDIR /build
RUN conan install /source --build outdated --install-folder=/build --output-folder=/build -pr:b=default
RUN cmake /source  -DCMAKE_TOOLCHAIN_FILE=/build/build/Release/generators/conan_toolchain.cmake -DCMAKE_POLICY_DEFAULT_CMP0091=NEW -DCMAKE_BUILD_TYPE=Release
RUN cmake --build .
RUN mkdir -p simulator/bin \
    && conan install -pr:b=default swtpm2/164-2020-192.1@ --build missing --generator virtualrunenv -o openssl:shared=False -o openssl:no_zlib=True \
    && source activate_run.sh \
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

#STOPSIGNAL SIGINT

CMD ["/entrypoint.sh"]

########################################################################################################################
