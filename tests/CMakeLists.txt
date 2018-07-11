# Copyright (c) Monetas AG, 2014

include_directories(SYSTEM ${CMAKE_CURRENT_SOURCE_DIR}/../deps/)

add_subdirectory(api)
add_subdirectory(blockchain)
add_subdirectory(client)
add_subdirectory(core)
add_subdirectory(contact)
add_subdirectory(network/zeromq)
