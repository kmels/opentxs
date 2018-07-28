# Copyright (c) 2018 The Open-Transactions developers
# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.

set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} ${PEDANTIC_CXX_FLAGS}")

set(dependency_include_dir
  ${CMAKE_CURRENT_SOURCE_DIR}/../deps/
)

include_directories(SYSTEM
  ${dependency_include_dir}
  ${dependency_include_dir}/ChaiScript/include
  ${ZMQ_INCLUDE_DIRS}
)

include_directories(
  ${CMAKE_CURRENT_BINARY_DIR}/../include
  ${CMAKE_CURRENT_SOURCE_DIR}/../include
  ${CMAKE_CURRENT_SOURCE_DIR}
)

if(LIBBITCOIN_EXPORT)
  include_directories(SYSTEM ${LIBBITCOIN_INCLUDE_DIRS})
endif()

if(KEYRING_GNOME)
  set(keyring libgnome-keyring.so)
endif()

add_subdirectory(iterator)
add_subdirectory(storage)
add_subdirectory(crypto)
add_subdirectory(core)
add_subdirectory(consensus)
add_subdirectory(ext)
add_subdirectory(network)
add_subdirectory(client)
add_subdirectory(api)
add_subdirectory(server)
add_subdirectory(contact)
add_subdirectory(ui)
add_subdirectory(util)

if(TREZORCRYPTO_EXPORT)
  set(trezor $<TARGET_OBJECTS:TrezorCrypto>)
else()
  set(trezor "")
endif()

if(CASH_LUCRE_EXPORT)
  set(lucre $<TARGET_OBJECTS:lucre>)
  include_directories(SYSTEM ${dependency_include_dir}/lucre/include)
else()
  set(lucre "")
endif()

if(OT_CASH_EXPORT)
  set(cash $<TARGET_OBJECTS:opentxs-cash>)
  add_subdirectory(cash)
else()
  set(cash "")
endif()

set(object-deps
  $<TARGET_OBJECTS:base64>
  $<TARGET_OBJECTS:irrxml>
  ${lucre}
  ${trezor}
  $<TARGET_OBJECTS:otprotob>
  $<TARGET_OBJECTS:opentxs-api-client>
  $<TARGET_OBJECTS:opentxs-api-crypto>
  $<TARGET_OBJECTS:opentxs-api-network>
  $<TARGET_OBJECTS:opentxs-api-storage>
  $<TARGET_OBJECTS:opentxs-api>
  ${cash}
  $<TARGET_OBJECTS:opentxs-client>
  $<TARGET_OBJECTS:opentxs-consensus>
  $<TARGET_OBJECTS:opentxs-core-contract-basket>
  $<TARGET_OBJECTS:opentxs-core-contract-peer>
  $<TARGET_OBJECTS:opentxs-core-contract>
  $<TARGET_OBJECTS:opentxs-core-crypto>
  $<TARGET_OBJECTS:opentxs-core-transaction>
  $<TARGET_OBJECTS:opentxs-core-util>
  $<TARGET_OBJECTS:opentxs-core>
  $<TARGET_OBJECTS:opentxs-crypto-key>
  $<TARGET_OBJECTS:opentxs-crypto-library>
  $<TARGET_OBJECTS:opentxs-crypto>
  $<TARGET_OBJECTS:opentxs-cron>
  $<TARGET_OBJECTS:opentxs-ext>
  $<TARGET_OBJECTS:opentxs-iterator>
  $<TARGET_OBJECTS:opentxs-network-zeromq>
  $<TARGET_OBJECTS:opentxs-network>
  $<TARGET_OBJECTS:opentxs-recurring>
  $<TARGET_OBJECTS:opentxs-script>
  $<TARGET_OBJECTS:opentxs-server>
  $<TARGET_OBJECTS:opentxs-storage>
  $<TARGET_OBJECTS:opentxs-storage-drivers>
  $<TARGET_OBJECTS:opentxs-storage-tree>
  $<TARGET_OBJECTS:opentxs-trade>
  $<TARGET_OBJECTS:opentxs-contact>
  $<TARGET_OBJECTS:opentxs-ui>
  $<TARGET_OBJECTS:opentxs-util>
)

set(cxx-install-headers
  "${CMAKE_CURRENT_SOURCE_DIR}/../include/opentxs/Exclusive.hpp"
  "${CMAKE_CURRENT_SOURCE_DIR}/../include/opentxs/Forward.hpp"
  "${CMAKE_CURRENT_SOURCE_DIR}/../include/opentxs/opentxs.hpp"
  "${CMAKE_CURRENT_SOURCE_DIR}/../include/opentxs/OT.hpp"
  "${CMAKE_CURRENT_SOURCE_DIR}/../include/opentxs/Pimpl.hpp"
  "${CMAKE_CURRENT_SOURCE_DIR}/../include/opentxs/Proto.hpp"
  "${CMAKE_CURRENT_SOURCE_DIR}/../include/opentxs/Shared.hpp"
  "${CMAKE_CURRENT_SOURCE_DIR}/../include/opentxs/SharedPimpl.hpp"
  "${CMAKE_CURRENT_SOURCE_DIR}/../include/opentxs/Types.hpp"
)

set(cxx-headers
  ${cxx-install-headers}
  "${CMAKE_CURRENT_SOURCE_DIR}/Internal.hpp"
  "${CMAKE_CURRENT_SOURCE_DIR}/Exclusive.tpp"
  "${CMAKE_CURRENT_SOURCE_DIR}/Shared.tpp"
  "${CMAKE_CURRENT_SOURCE_DIR}/stdafx.hpp"
)

set(MODULE_NAME opentxs)

macro(ndk_gdb_debuggable TARGET_NAME)
    get_property(TARGET_LOCATION TARGET ${TARGET_NAME} PROPERTY LOCATION)
    
    # create custom target that depends on the real target so it gets executed afterwards
    add_custom_target(NDK_GDB ALL) 
    add_dependencies(NDK_GDB ${TARGET_NAME})
    
    set(GDB_SOLIB_PATH ${PROJECT_SOURCE_DIR}/obj/local/${ANDROID_NDK_ABI_NAME}/)
    
    # 1. generate essential Android Makefiles
    file(WRITE ${PROJECT_SOURCE_DIR}/jni/Android.mk "APP_ABI := ${ANDROID_NDK_ABI_NAME}\n")
    file(WRITE ${PROJECT_SOURCE_DIR}/jni/Application.mk "APP_ABI := ${ANDROID_NDK_ABI_NAME}\n")

    # 2. generate gdb.setup
    get_directory_property(PROJECT_INCLUDES DIRECTORY ${PROJECT_SOURCE_DIR} INCLUDE_DIRECTORIES)
    string(REGEX REPLACE ";" " " PROJECT_INCLUDES "${PROJECT_INCLUDES}")
    file(WRITE ${PROJECT_SOURCE_DIR}/libs/${ANDROID_NDK_ABI_NAME}/gdb.setup "set solib-search-path ${GDB_SOLIB_PATH}\n")
    file(APPEND ${PROJECT_SOURCE_DIR}/libs/${ANDROID_NDK_ABI_NAME}/gdb.setup "directory ${PROJECT_INCLUDES}\n")

    # 3. copy gdbserver executable
    set (ANDROID_NDK /usr/local/share/ndk/android-ndk-r17b)
    file(COPY ${ANDROID_NDK}/prebuilt/android-arm/gdbserver/gdbserver DESTINATION ${PROJECT_SOURCE_DIR}/libs/${ANDROID_NDK_ABI_NAME}/)

    # 4. copy lib to obj
    add_custom_command(TARGET NDK_GDB POST_BUILD COMMAND mkdir -p ${GDB_SOLIB_PATH})
    add_custom_command(TARGET NDK_GDB POST_BUILD COMMAND cp ${TARGET_LOCATION} ${GDB_SOLIB_PATH})

    # 5. strip symbols
    add_custom_command(TARGET NDK_GDB POST_BUILD COMMAND ${CMAKE_STRIP} ${TARGET_LOCATION})
endmacro()

add_library(${MODULE_NAME} SHARED
  ${cxx-headers}
  ${object-deps}
  ${CMAKE_CURRENT_SOURCE_DIR}/Factory.hpp
  ${CMAKE_CURRENT_SOURCE_DIR}/Globals.cpp
  ${CMAKE_CURRENT_SOURCE_DIR}/OT.cpp
)

ndk_gdb_debuggable(${MODULE_NAME})

add_library(${MODULE_NAME}_static STATIC
  ${cxx-headers}
  ${object-deps}
)

if(NOT WIN32)
  set_target_properties(${MODULE_NAME}_static PROPERTIES OUTPUT_NAME ${MODULE_NAME})
endif()

target_link_libraries(${MODULE_NAME}
  PRIVATE
  Threads::Threads
  ${OPENSSL_LIBRARIES}
  ${OPENTXS_PROTO_LIBRARIES}
  ${PROTOBUF_LITE_LIBRARIES}
  ${ZLIB_LIBRARY}
  ${SODIUM_LIBRARY}
  ${OPENTXS_SYSTEM_LIBRARIES}
  ${keyring}
  ${CMAKE_DL_LIBS}
  ${ZMQ_LIBRARIES}
)

if (LIBSECP256K1_EXPORT)
  target_link_libraries(${MODULE_NAME} PRIVATE ${LIBSECP256K1_LIBRARY})
endif()

if (LIBBITCOIN_EXPORT)
  target_link_libraries(${MODULE_NAME} PRIVATE ${LIBBITCOIN_LIBRARIES})
endif()

if(OT_DHT)
  target_link_libraries(${MODULE_NAME} PRIVATE ${OPENDHT_LIBRARIES} ${GNUTLS_LIBRARIES})
endif()

if (OT_STORAGE_SQLITE)
    target_link_libraries(${MODULE_NAME} PRIVATE ${SQLITE3_LIBRARIES})
endif()

if (OT_STORAGE_FS)
    target_link_libraries(${MODULE_NAME} PRIVATE ${Boost_SYSTEM_LIBRARIES} ${Boost_FILESYSTEM_LIBRARIES} ${Boost_IOSTREAMS_LIBRARIES})
endif()

if(WIN32)
  add_custom_command(TARGET ${MODULE_NAME} POST_BUILD
    COMMAND ${CMAKE_COMMAND} -E copy_if_different
    "${CMAKE_BINARY_DIR}/lib/$<CONFIGURATION>/${MODULE_NAME}.dll"
    "${CMAKE_BINARY_DIR}/bin/$<CONFIGURATION>/${MODULE_NAME}.dll")

  add_custom_command(TARGET ${MODULE_NAME} POST_BUILD
    COMMAND ${CMAKE_COMMAND} -E copy_if_different
    "${CMAKE_BINARY_DIR}/lib/$<CONFIGURATION>/${MODULE_NAME}.pdb"
    "${CMAKE_BINARY_DIR}/bin/$<CONFIGURATION>/${MODULE_NAME}.pdb")
endif()

if(NOT WIN32)
  include(GNUInstallDirs)
  install(TARGETS ${MODULE_NAME} ${MODULE_NAME}_static
          DESTINATION ${CMAKE_INSTALL_LIBDIR}
          EXPORT opentxsTargets
          COMPONENT main)
endif()

install(FILES ${cxx-install-headers}
        DESTINATION include/opentxs
        COMPONENT dev)

install(DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}../include/opentxs/interface
        DESTINATION include/opentxs/interface
        COMPONENT dev
        FILES_MATCHING PATTERN "*.hpp")

