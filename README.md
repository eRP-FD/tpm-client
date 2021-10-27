## TPM Client Access Library

#### About

This repository contains the TPM client -- a C++ library used by the VAU instances to securely use and communicate with the underlying physical `Trusted Platform Module`. For fulfilling that purpose, the library offers a straightforward and clean API (for VAU's needs), while internally using a third party dependency -- a library called [TSS](https://github.com/kgoldman/ibmtss) -- which does the actual heavy lifting of talking to the TPM hardware.

#### How to build on Linux

- install dependencies: 
  - `conan` (perhaps installed via `pip`, which itself needs `python`)
  - `cmake`
  - `make`
  - `gcc`

- add the eRP Conan repository from Nexus: `conan remote add erp https://nexus.epa-dev.net/repository/erp-conan-internal`

- `conan profile update settings.compiler.libcxx=libstdc++11 default`

- update your (perhaps `default`) Conan profile for the right build type (`Debug` or `Release`): `conan profile update settings.build_type=Debug default`

- create a build folder for the right build type: `mkdir build-debug`

- change working directory into the newly created folder and invoke CMake with the right build type: `cmake -DCMAKE_BUILD_TYPE=Debug ..`, eventually if you want to build tests as well then add `-DBUILD_TESTS=1`

- build the project: `make -j4`

- artefacts can be found in the build folder under `lib` (and tests under `bin`)
