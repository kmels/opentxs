// Copyright (c) 2018 The Open-Transactions developers
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

#pragma once

#include "Internal.hpp"

#include "opentxs/ui/ContactSection.hpp"
#include "opentxs/ui/Widget.hpp"

#include "internal/ui/UI.hpp"

namespace opentxs::ui::implementation
{
class ContactSectionBlank final : public ContactRowInternal
{
public:
#if OT_QT
    int columnCount(const QModelIndex& parent = QModelIndex()) const override
    {
        return 0;
    }
    QVariant data(const QModelIndex& index, int role = Qt::DisplayRole)
        const override
    {
        return {};
    }
    QModelIndex index(
        int row,
        int column,
        const QModelIndex& parent = QModelIndex()) const override
    {
        return {};
    }
    QModelIndex parent(const QModelIndex& index) const override { return {}; }
    int rowCount(const QModelIndex& parent = QModelIndex()) const override
    {
        return 0;
    }
#endif
    std::string Name(const std::string& lang) const override { return {}; }
    OTUIContactSubsection First() const override
    {
        const std::shared_ptr<const ui::ContactSubsection> empty;

        return OTUIContactSubsection{empty};
    }
    bool Last() const override { return true; }
    OTUIContactSubsection Next() const override
    {
        const std::shared_ptr<const ui::ContactSubsection> empty;

        return OTUIContactSubsection{empty};
    }
    proto::ContactSectionName Type() const override { return {}; }
    bool Valid() const override { return false; }
    OTIdentifier WidgetID() const override { return Identifier::Factory(); }

    void reindex(
        const implementation::ContactSortKey&,
        const implementation::CustomData&) override
    {
    }
    bool last(const ContactSectionRowID&) const override { return false; }
    std::string ContactID() const override { return {}; }

    ContactSectionBlank() = default;
    ~ContactSectionBlank() = default;

private:
    ContactSectionBlank(const ContactSectionBlank&) = delete;
    ContactSectionBlank(ContactSectionBlank&&) = delete;
    ContactSectionBlank& operator=(const ContactSectionBlank&) = delete;
    ContactSectionBlank& operator=(ContactSectionBlank&&) = delete;
};
}  // namespace opentxs::ui::implementation
