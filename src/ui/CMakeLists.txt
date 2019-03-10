# Copyright (c) 2018 The Open-Transactions developers
# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.

if(OT_WITH_QT)
  add_definitions(${Qt5Core_DEFINITIONS})
  add_definitions(${Qt5Gui_DEFINITIONS})
  add_definitions(${Qt5Widgets_DEFINITIONS})
endif()

set(cxx-sources
  AccountActivity.cpp
  AccountList.cpp
  AccountListItem.cpp
  AccountSummary.cpp
  AccountSummaryItem.cpp
  ActivitySummary.cpp
  ActivitySummaryItem.cpp
  ActivityThread.cpp
  ActivityThreadItem.cpp
  BalanceItem.cpp
  ChequeBalanceItem.cpp
  Contact.cpp
  ContactItem.cpp
  ContactList.cpp
  ContactListItem.cpp
  ContactSection.cpp
  ContactSubsection.cpp
  IssuerItem.cpp
  MailItem.cpp
  MessagableList.cpp
  PayableList.cpp
  PayableListItem.cpp
  PaymentItem.cpp
  PendingSend.cpp
  Profile.cpp
  ProfileItem.cpp
  ProfileSection.cpp
  ProfileSubsection.cpp
  TransferBalanceItem.cpp
  Widget.cpp
)

set(cxx-install-headers
  "${CMAKE_CURRENT_SOURCE_DIR}/../../include/opentxs/ui/AccountActivity.hpp"
  "${CMAKE_CURRENT_SOURCE_DIR}/../../include/opentxs/ui/AccountList.hpp"
  "${CMAKE_CURRENT_SOURCE_DIR}/../../include/opentxs/ui/AccountListItem.hpp"
  "${CMAKE_CURRENT_SOURCE_DIR}/../../include/opentxs/ui/AccountSummary.hpp"
  "${CMAKE_CURRENT_SOURCE_DIR}/../../include/opentxs/ui/AccountSummaryItem.hpp"
  "${CMAKE_CURRENT_SOURCE_DIR}/../../include/opentxs/ui/ActivitySummary.hpp"
  "${CMAKE_CURRENT_SOURCE_DIR}/../../include/opentxs/ui/ActivitySummaryItem.hpp"
  "${CMAKE_CURRENT_SOURCE_DIR}/../../include/opentxs/ui/ActivityThread.hpp"
  "${CMAKE_CURRENT_SOURCE_DIR}/../../include/opentxs/ui/ActivityThreadItem.hpp"
  "${CMAKE_CURRENT_SOURCE_DIR}/../../include/opentxs/ui/BalanceItem.hpp"
  "${CMAKE_CURRENT_SOURCE_DIR}/../../include/opentxs/ui/Contact.hpp"
  "${CMAKE_CURRENT_SOURCE_DIR}/../../include/opentxs/ui/ContactItem.hpp"
  "${CMAKE_CURRENT_SOURCE_DIR}/../../include/opentxs/ui/ContactList.hpp"
  "${CMAKE_CURRENT_SOURCE_DIR}/../../include/opentxs/ui/ContactListItem.hpp"
  "${CMAKE_CURRENT_SOURCE_DIR}/../../include/opentxs/ui/ContactSection.hpp"
  "${CMAKE_CURRENT_SOURCE_DIR}/../../include/opentxs/ui/ContactSubsection.hpp"
  "${CMAKE_CURRENT_SOURCE_DIR}/../../include/opentxs/ui/IssuerItem.hpp"
  "${CMAKE_CURRENT_SOURCE_DIR}/../../include/opentxs/ui/List.hpp"
  "${CMAKE_CURRENT_SOURCE_DIR}/../../include/opentxs/ui/ListRow.hpp"
  "${CMAKE_CURRENT_SOURCE_DIR}/../../include/opentxs/ui/MessagableList.hpp"
  "${CMAKE_CURRENT_SOURCE_DIR}/../../include/opentxs/ui/PayableList.hpp"
  "${CMAKE_CURRENT_SOURCE_DIR}/../../include/opentxs/ui/PayableListItem.hpp"
  "${CMAKE_CURRENT_SOURCE_DIR}/../../include/opentxs/ui/Profile.hpp"
  "${CMAKE_CURRENT_SOURCE_DIR}/../../include/opentxs/ui/ProfileItem.hpp"
  "${CMAKE_CURRENT_SOURCE_DIR}/../../include/opentxs/ui/ProfileSection.hpp"
  "${CMAKE_CURRENT_SOURCE_DIR}/../../include/opentxs/ui/ProfileSubsection.hpp"
  "${CMAKE_CURRENT_SOURCE_DIR}/../../include/opentxs/ui/Widget.hpp"
)

set(cxx-headers
  ${cxx-install-headers}
  "${CMAKE_CURRENT_SOURCE_DIR}/../internal/ui/UI.hpp"
  "${CMAKE_CURRENT_SOURCE_DIR}/AccountActivity.hpp"
  "${CMAKE_CURRENT_SOURCE_DIR}/AccountList.hpp"
  "${CMAKE_CURRENT_SOURCE_DIR}/AccountListItem.hpp"
  "${CMAKE_CURRENT_SOURCE_DIR}/AccountListItemBlank.hpp"
  "${CMAKE_CURRENT_SOURCE_DIR}/AccountSummary.hpp"
  "${CMAKE_CURRENT_SOURCE_DIR}/AccountSummaryItem.hpp"
  "${CMAKE_CURRENT_SOURCE_DIR}/AccountSummaryItemBlank.hpp"
  "${CMAKE_CURRENT_SOURCE_DIR}/ActivitySummary.hpp"
  "${CMAKE_CURRENT_SOURCE_DIR}/ActivitySummaryItem.hpp"
  "${CMAKE_CURRENT_SOURCE_DIR}/ActivitySummaryItemBlank.hpp"
  "${CMAKE_CURRENT_SOURCE_DIR}/ActivityThread.hpp"
  "${CMAKE_CURRENT_SOURCE_DIR}/ActivityThreadItem.hpp"
  "${CMAKE_CURRENT_SOURCE_DIR}/ActivityThreadItemBlank.hpp"
  "${CMAKE_CURRENT_SOURCE_DIR}/BalanceItem.hpp"
  "${CMAKE_CURRENT_SOURCE_DIR}/BalanceItemBlank.hpp"
  "${CMAKE_CURRENT_SOURCE_DIR}/Contact.hpp"
  "${CMAKE_CURRENT_SOURCE_DIR}/ContactItem.hpp"
  "${CMAKE_CURRENT_SOURCE_DIR}/ContactItemBlank.hpp"
  "${CMAKE_CURRENT_SOURCE_DIR}/ContactList.hpp"
  "${CMAKE_CURRENT_SOURCE_DIR}/ContactListItem.hpp"
  "${CMAKE_CURRENT_SOURCE_DIR}/ContactListItemBlank.hpp"
  "${CMAKE_CURRENT_SOURCE_DIR}/ContactSection.hpp"
  "${CMAKE_CURRENT_SOURCE_DIR}/ContactSectionBlank.hpp"
  "${CMAKE_CURRENT_SOURCE_DIR}/ContactSubsection.hpp"
  "${CMAKE_CURRENT_SOURCE_DIR}/ContactSubsectionBlank.hpp"
  "${CMAKE_CURRENT_SOURCE_DIR}/IssuerItem.hpp"
  "${CMAKE_CURRENT_SOURCE_DIR}/IssuerItemBlank.hpp"
  "${CMAKE_CURRENT_SOURCE_DIR}/List.hpp"
  "${CMAKE_CURRENT_SOURCE_DIR}/MailItem.hpp"
  "${CMAKE_CURRENT_SOURCE_DIR}/MessagableList.hpp"
  "${CMAKE_CURRENT_SOURCE_DIR}/PayableList.hpp"
  "${CMAKE_CURRENT_SOURCE_DIR}/PayableListItem.hpp"
  "${CMAKE_CURRENT_SOURCE_DIR}/PayableListItemBlank.hpp"
  "${CMAKE_CURRENT_SOURCE_DIR}/PendingSend.hpp"
  "${CMAKE_CURRENT_SOURCE_DIR}/Profile.hpp"
  "${CMAKE_CURRENT_SOURCE_DIR}/ProfileItem.hpp"
  "${CMAKE_CURRENT_SOURCE_DIR}/ProfileItemBlank.hpp"
  "${CMAKE_CURRENT_SOURCE_DIR}/ProfileSection.hpp"
  "${CMAKE_CURRENT_SOURCE_DIR}/ProfileSectionBlank.hpp"
  "${CMAKE_CURRENT_SOURCE_DIR}/ProfileSubsection.hpp"
  "${CMAKE_CURRENT_SOURCE_DIR}/ProfileSubsectionBlank.hpp"
  "${CMAKE_CURRENT_SOURCE_DIR}/Row.hpp"
  "${CMAKE_CURRENT_SOURCE_DIR}/RowType.hpp"
  "${CMAKE_CURRENT_SOURCE_DIR}/Widget.hpp"
)

if(OT_WITH_QT)
  QT5_WRAP_CPP( MOC_SRCS ${cxx-headers} )
else()
  set(MOC_SRCS "")
endif()

set(MODULE_NAME opentxs-ui)

if(WIN32)
  # suppress warnings about exported internal symbols (global log stream objects)
  add_definitions(-DOTLOG_IMPORT)

  # suppress linker warnings about locallly defined imported symbols
  set(CMAKE_SHARED_LINKER_FLAGS "${CMAKE_SHARED_LINKER_FLAGS} /ignore:4049 /ignore:4217")

  configure_file(
    ${CMAKE_CURRENT_SOURCE_DIR}/../../cmake/windll.rc.in
    ${CMAKE_CURRENT_BINARY_DIR}/module.rc
    @ONLY
  )

  # we have an extra Windows-specific file to compile
  add_library(${MODULE_NAME} OBJECT
    ${cxx-sources}
    ${cxx-headers}
    ${MOC_SRCS}
    ${CMAKE_CURRENT_BINARY_DIR}/module.rc
  )
else()
  add_library(${MODULE_NAME} OBJECT
    ${cxx-sources}
    ${cxx-headers}
    ${MOC_SRCS}
  )
endif()

install(FILES ${cxx-install-headers}
        DESTINATION include/opentxs/ui
        COMPONENT dev)

set_property(TARGET ${MODULE_NAME} PROPERTY POSITION_INDEPENDENT_CODE 1)
set_lib_property(${MODULE_NAME})
