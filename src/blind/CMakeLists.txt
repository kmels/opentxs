# Copyright (c) 2018 The Open-Transactions developers
# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.

set(MODULE_NAME opentxs-blind)

set(cxx-sources
  mint/Lucre.cpp
  token/Lucre.cpp
  Lucre.cpp
  Mint.cpp
  Purse.cpp
  Token.cpp
)

set(cxx-install-headers
  "${CMAKE_CURRENT_SOURCE_DIR}/../../include/opentxs/blind/Mint.hpp"
  "${CMAKE_CURRENT_SOURCE_DIR}/../../include/opentxs/blind/Purse.hpp"
  "${CMAKE_CURRENT_SOURCE_DIR}/../../include/opentxs/blind/Token.hpp"
)

set(cxx-headers
  ${cxx-install-headers}
  mint/Lucre.hpp
  token/Lucre.hpp
  Lucre.hpp
  Mint.hpp
  Purse.hpp
  Token.hpp
)

if(WIN32)
  configure_file(
    ${CMAKE_CURRENT_SOURCE_DIR}/../../cmake/windll.rc.in
    ${CMAKE_CURRENT_BINARY_DIR}/module.rc
    @ONLY
  )

  # we have an extra Windows-specific file to compile
  add_library(${MODULE_NAME} OBJECT
  ${cxx-sources}
  ${cxx-headers}
    ${CMAKE_CURRENT_BINARY_DIR}/module.rc
  )
else()
  add_library(${MODULE_NAME} OBJECT
    ${cxx-sources}
    ${cxx-headers}
  )
endif()

install(FILES ${cxx-install-headers}
        DESTINATION include/opentxs/blind
        COMPONENT dev)

set_property(TARGET ${MODULE_NAME} PROPERTY POSITION_INDEPENDENT_CODE 1)
set_lib_property(${MODULE_NAME})
target_include_directories(${MODULE_NAME} PUBLIC ${OT_SSL_HEADERS})
target_include_directories(${MODULE_NAME} PUBLIC "../../deps")
target_include_directories(${MODULE_NAME} PUBLIC "../../deps/lucre/include")
