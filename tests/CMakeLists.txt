# Copyright (c) Monetas AG, 2014

include_directories(SYSTEM ${CMAKE_CURRENT_SOURCE_DIR}/../deps/)


add_subdirectory(api)
if(OT_CRYPTO_SUPPORTED_KEY_HD)
  add_subdirectory(blockchain)
endif()
add_subdirectory(client)
add_subdirectory(core)
add_subdirectory(contact)
add_subdirectory(crypto)
add_subdirectory(network/zeromq)
