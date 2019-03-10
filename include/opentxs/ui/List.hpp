// Copyright (c) 2018 The Open-Transactions developers
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

#ifndef OPENTXS_UI_LIST_HPP
#define OPENTXS_UI_LIST_HPP

#include "opentxs/Forward.hpp"

#include "opentxs/ui/Widget.hpp"

#if OT_QT
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wctor-dtor-privacy"
#include <QtCore/qabstractitemmodel.h>
#pragma GCC diagnostic pop
#endif

#ifdef SWIG
// clang-format off
%rename(UIList) opentxs::ui::List;
// clang-format on
#endif  // SWIG

namespace opentxs
{
namespace ui
{
class List :
#if OT_QT
    virtual public QAbstractItemModel,
#endif
    virtual public Widget
{
#if OT_QT
    Q_OBJECT
#endif

public:
    EXPORT virtual ~List() = default;

protected:
    List() = default;

private:
    List(const List&) = delete;
    List(List&&) = delete;
    List& operator=(const List&) = delete;
    List& operator=(List&&) = delete;
};
}  // namespace ui
}  // namespace opentxs
#endif
