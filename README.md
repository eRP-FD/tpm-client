## TPM Client Access Library

#### About

Dieses Repository enthält den TPM-Client - eine C++-Bibliothek, die von den VAU-Instanzen verwendet wird, um das zugrunde liegende physische "Trusted Platform Module" sicher zu nutzen und mit ihm zu kommunizieren. Um diesen Zweck zu erfüllen, bietet die Bibliothek eine einfache und saubere API (für die Bedürfnisse von VAU), während sie intern eine Abhängigkeit von einer Drittpartei nutzt - eine Bibliothek namens [TSS](https://github.com/kgoldman/ibmtss) - die die eigentliche Arbeit der Kommunikation mit der TPM-Hardware übernimmt.

#### How to build on Linux

- Installieren sie folgende Abhängigkeiten:
  - `conan` (perhaps installed via `pip`, which itself needs `python`)
  - `cmake`
  - `make`
  - `gcc`

- Fügen Sie das eRP Conan-Repository von Nexus hinzu: `conan remote add erp https://nexus.epa-dev.net/repository/erp-conan-internal`

- `conan profile update settings.compiler.libcxx=libstdc++11 default`

- Aktualisieren Sie Ihr (vielleicht `default`) Conan-Profil für den richtigen Build-Typ (`Debug` oder `Release`): `conan profile update settings.build_type=Debug default`

- Erstellen Sie einen Build-Ordner für den richtigen Build-Typ: mkdir build-debug

- Wechseln Sie das Arbeitsverzeichnis in den neu erstellten Ordner und rufen Sie CMake mit dem richtigen Build-Typ auf: `cmake -DCMAKE_BUILD_TYPE=Debug ..`, eventuell, wenn Sie auch Tests bauen wollen, fügen Sie `-DBUILD_TESTS=1` hinzu

- Bauen Sie das Projekt: `make -j4`

- Artefakte können im Build-Ordner unter `lib` (und Tests unter `bin`) gefunden werden
