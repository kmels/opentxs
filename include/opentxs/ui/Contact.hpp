// Copyright (c) 2018 The Open-Transactions developers
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

#ifndef OPENTXS_UI_CONTACT_HPP
#define OPENTXS_UI_CONTACT_HPP

#include "opentxs/Forward.hpp"

#include "opentxs/ui/List.hpp"
#include "opentxs/Proto.hpp"

#include <string>

#ifdef SWIG
// clang-format off
%rename(UIContact) opentxs::ui::Contact;
// clang-format on
#endif  // SWIG

namespace opentxs
{
namespace ui
{
class Contact : virtual public List
{
#if OT_QT
    Q_OBJECT
#endif

public:
    EXPORT virtual std::string ContactID() const = 0;
    EXPORT virtual std::string DisplayName() const = 0;
    EXPORT virtual opentxs::SharedPimpl<opentxs::ui::ContactSection> First()
        const = 0;
    EXPORT virtual opentxs::SharedPimpl<opentxs::ui::ContactSection> Next()
        const = 0;
    EXPORT virtual std::string PaymentCode() const = 0;

    EXPORT virtual ~Contact() = default;

protected:
    Contact() = default;

private:
    Contact(const Contact&) = delete;
    Contact(Contact&&) = delete;
    Contact& operator=(const Contact&) = delete;
    Contact& operator=(Contact&&) = delete;
};
}  // namespace ui
}  // namespace opentxs
#endif
