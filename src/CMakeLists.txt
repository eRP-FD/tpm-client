# (C) Copyright IBM Deutschland GmbH 2021
# (C) Copyright IBM Corp. 2021
# SPDX-License-Identifier: CC BY-NC-ND 3.0 DE

########################################################################################################################

# define the name of a new target
#
set(TARGET_NAME "tpmclient")

# list its source files
#
set(SOURCE_FILES "Exception.cpp"
                 "Client.cpp"
                 "ClientUser.cpp"
                 "Session.cpp"
                 "StorageIndex.cpp"
                 "StorageIndexMap.cpp"
                 "Types.cpp"
                 "Utils.cpp")

# list its public API header files
#
set(PUBLIC_HEADERS "Client.h"
                   "Exception.h"
                   "Session.h"
                   "Types.h")

########################################################################################################################

# define and configure the target by specifying its name, type and list of source files
#
configure_target(${TARGET_NAME} "SHARED_LIBRARY" "${SOURCE_FILES}")

########################################################################################################################

# install the target
#
install_target(${TARGET_NAME} "${PUBLIC_HEADERS}")

########################################################################################################################
