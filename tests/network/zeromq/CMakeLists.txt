# Copyright (c) 2018 The Open-Transactions developers
# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.

set(name unittests-opentxs-network-zeromq)

set(cxx-sources
  ${PROJECT_SOURCE_DIR}/tests/main.cpp
  Test_DealerReply.cpp
  Test_DealerRouter.cpp
  Test_DealerSocket.cpp
  Test_Frame.cpp
  Test_FrameIterator.cpp
  Test_FrameSection.cpp
  Test_ListenCallback.cpp
  Test_Message.cpp
  Test_PairSocket.cpp
  Test_PublishSocket.cpp
  Test_PublishSubscribe.cpp
  Test_PushPull.cpp
  Test_ReplyCallback.cpp
  Test_ReplySocket.cpp
  Test_RequestReply.cpp
  Test_RequestRouter.cpp
  Test_RequestSocket.cpp
  Test_RouterDealer.cpp
  Test_RouterSocket.cpp
  Test_SubscribeSocket.cpp
  ${PROJECT_SOURCE_DIR}/tests/OTTestEnvironment.cpp
)

include_directories(
  ${PROJECT_SOURCE_DIR}/include
  ${PROJECT_SOURCE_DIR}/tests
  ${GTEST_INCLUDE_DIRS}
)

add_executable(${name} ${cxx-sources})
target_link_libraries(${name} opentxs ${GTEST_BOTH_LIBRARIES} ${ZMQ_LIBRARIES})
set_target_properties(${name} PROPERTIES RUNTIME_OUTPUT_DIRECTORY ${PROJECT_BINARY_DIR}/tests)
add_test(${name} ${PROJECT_BINARY_DIR}/tests/${name} --gtest_output=xml:gtestresults.xml)
target_include_directories(${name} PRIVATE ${OT_ZEROMQ_HEADERS})

if(OT_WITH_QT)
  target_link_libraries(${name} ${Qt5Core_LIBRARIES} ${Qt5Gui_LIBRARIES} ${Qt5Widgets_LIBRARIES})
endif()

