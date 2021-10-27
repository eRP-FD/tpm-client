#!/usr/bin/env python3

###################################################################################################

from conans import CMake
from conans import ConanFile
from conans import tools

###################################################################################################

import os

###################################################################################################

class TpmClientPackage(ConanFile):

    # custom properties for usage by this specific recipe's code, not by the Conan SDK

    _build_tests_cmake_argument = 'BUILD_TESTS'

    _hardware_tpm_cmake_argument = 'HARDWARE_TPM'

    _test_build_requires = ['gtest/1.11.0']

    _cmake = None

    # Conan properties, used by the Conan SDK

    name = 'tpmclient'

    homepage = 'https://github.ibmgcloud.net/eRp/tpm-client'

    description = 'The TPM client access library'

    author = 'Theodor Serbana <theodor.serbana@ibm.com>'

    license = 'proprietary'

    url = 'https://github.ibmgcloud.net/eRp/tpm-client'

    options = {'with_tests': [True, False]}

    default_options = {'with_tests': False,
                       'gtest:build_gmock': False,
                       'gtest:shared': True,
                       'tss:with_tpm_1_2': False,
                       'tss:with_tpm_2_0': True,
                       'tss:with_hardware_tpm': False}

    settings = {'os': ['Linux', 'Windows'],
                'compiler': ['gcc', 'Visual Studio'],
                'build_type': ['Debug', 'Release', 'RelWithDebInfo'],
                'arch': ['x86', 'x86_64']}

    generators = ['cmake']

    exports_sources = '*'

    build_requires = []

    requires = ['openssl/1.1.1l',
                'swtpm2/1636',
                'tss/1.6.0']

    def _get_cmake(self):
        if self._cmake:
            return self._cmake

        self._cmake = CMake(self, set_cmake_flags=True)

        # build the tests if option was given
        #
        if self.options.with_tests:
            self._cmake.definitions[self._build_tests_cmake_argument] = 1

        if self.options['tss'].with_hardware_tpm:
            self._cmake.definitions[self._hardware_tpm_cmake_argument] = 1

        # call cmake configure
        #
        self._cmake.configure()
        return self._cmake

    def set_version(self):
        if not self.version:
            git = tools.Git()
            self.version = git.run("describe --exclude 'v-*' --match 'v*'")[1:]

    def build_requirements(self):
        if self.options.with_tests:
            for dependency in self._test_build_requires:
                self.build_requires(dependency)

    def build(self):
        # build the source code
        #
        cmake = self._get_cmake()
        cmake.build()

        # run the tests if option was given
        #
        if self.options.with_tests:
            cmake.test()

    def package(self):
        # call the CMake install target 
        #
        cmake = self._get_cmake()
        cmake.install()

    def package_info(self):
        self.cpp_info.libs = tools.collect_libs(self)

    def imports(self):
        self.copy('tpm_server*', os.path.join('simulator', 'bin'), 'bin')

        self.copy('*crypto*.dll*', 'bin', 'bin')
        self.copy('*tss*.dll*',  'bin', 'bin')

        self.copy('*crypto*.so*', 'lib', 'lib')
        self.copy('*tss*.so*', 'lib', 'lib')

###################################################################################################
