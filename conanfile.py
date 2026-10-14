#!/usr/bin/env python3

# (C) Copyright IBM Deutschland GmbH 2021, 2023
# (C) Copyright IBM Corp 2021, 2023
#
# non-exclusively licensed to gematik GmbH

###################################################################################################

from conan import ConanFile
from conan.errors import ConanInvalidConfiguration
from conan.tools.build import check_min_cppstd
from conan.tools.cmake import CMake, CMakeDeps, CMakeToolchain, cmake_layout
from conan.tools.files import copy
from conan.tools.microsoft import check_min_vs, is_msvc
from conan.tools.scm import Version, Git

import os
import shutil

required_conan_version = ">=1.53.0"


class TpmClientPackage(ConanFile):
    name = "tpmclient"
    description = "The TPM client access library"
    license = "proprietary"
    url = "https://github.ibmgcloud.net/eRp/tpm-client"
    homepage = "https://github.ibmgcloud.net/eRp/tpm-client"
    package_type = "library"
    options = {"shared": [True, False], "fPIC": [True, False], "with_tests": [True, False]}
    settings = "os", "arch", "compiler", "build_type"
    default_options = {
        "shared": False,
        "fPIC": True,
        "with_tests": False,
        "gtest/*:build_gmock": False,
        "gtest/*:shared": True,
        "tss/*:with_tpm_1_2": False,
        "tss/*:with_tpm_2_0": True,
        "tss/*:with_hardware_tpm": False,
    }

    @property
    def _min_cppstd(self):
        return 17

    @property
    def _compilers_minimum_version(self):
        return {
            "gcc": "7",
            "clang": "7",
            "apple-clang": "10",
        }

    def export_sources(self):
        git = Git(self)
        included = git.included_files()
        for i in included:
            dst = os.path.join(self.export_sources_folder, i)
            os.makedirs(os.path.dirname(dst), exist_ok=True)
            shutil.copy2(i, dst)

    def config_options(self):
        if self.settings.os == "Windows":
            del self.options.fPIC

    def configure(self):
        if self.options.shared:
            self.options.rm_safe("fPIC")

    def requirements(self):
        self.requires("openssl/[>=1.1 <4]")
        self.requires("tss/2.0.1")
        if self.options.with_tests:
            self.test_requires("gtest/1.11.0")

    def validate(self):
        # validate the minimum cpp standard supported. For C++ projects only
        if self.settings.compiler.cppstd:
            check_min_cppstd(self, self._min_cppstd)
        check_min_vs(self, 191)
        if not is_msvc(self):
            minimum_version = self._compilers_minimum_version.get(str(self.settings.compiler), False)
            if minimum_version and Version(self.settings.compiler.version) < minimum_version:
                raise ConanInvalidConfiguration(
                    f"{self.ref} requires C++{self._min_cppstd}, which your compiler does not support."
                )

    def generate(self):
        tc = CMakeToolchain(self)
        if self.options.with_tests:
            tc.variables["BUILD_TESTS"] = True
        if self.dependencies["tss"].options.with_hardware_tpm:
            tc.variables["HARDWARE_TPM"] = True
        tc.generate()
        tc = CMakeDeps(self)
        tc.generate()

    def set_version(self):
        if not self.version:
            git = Git(self, folder=self.recipe_folder)
            self.version = git.run('describe --tags --abbrev=0 --match "v-[0-9\.]*"')[2:].lower()

    def build(self):
        cmake = CMake(self)
        cmake.configure()
        cmake.build()

        # run the tests if option was given
        #
        if self.options.with_tests:
            cmake.test()

    def package(self):
        cmake = CMake(self)
        cmake.install()

    def package_info(self):
        self.cpp_info.libs = ["tpmclient"]


###################################################################################################
