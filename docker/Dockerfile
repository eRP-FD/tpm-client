# (C) Copyright IBM Deutschland GmbH 2021
# (C) Copyright IBM Corp. 2021
# SPDX-License-Identifier: CC BY-NC-ND 3.0 DE

########################################################################################################################

FROM conanio/gcc10:1.40.3 AS prerequisites

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
WORKDIR /build
RUN cmake -S /source -DCMAKE_BUILD_TYPE=Release -DBUILD_TESTS=1
RUN cmake --build .

# clean up
#
RUN rm -rf $HOME/.conan \
           $HOME/.local \
           /source

########################################################################################################################

FROM ubuntu:21.10 AS run

# make a clean run directory
#
WORKDIR /run
RUN rm -rf *
COPY --from=build /build/simulator .

STOPSIGNAL SIGINT

CMD ["/run/bin/tpm_server"]

########################################################################################################################
