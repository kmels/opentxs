// Copyright (c) 2018 The Open-Transactions developers
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

#ifndef OPENTXS_ITERATOR_BIDIRECTIONAL_HPP
#define OPENTXS_ITERATOR_BIDIRECTIONAL_HPP

#include "opentxs/Forward.hpp"

#include <cstddef>
#include <iterator>
#include <limits>
#include <stdexcept>

#ifdef _WIN32
#undef min
#undef max
#endif

namespace opentxs
{
namespace iterator
{
template <typename P, typename C>
class Bidirectional
{
public:
    using value_type = C;
    using pointer = value_type*;
    using reference = value_type&;
    using difference_type = std::ptrdiff_t;
    using iterator_category = std::bidirectional_iterator_tag;

    EXPORT Bidirectional(P* parent, std::size_t position = 0)
        : position_{position}
        , parent_{parent}
    {
    }
    EXPORT Bidirectional() = default;
    EXPORT Bidirectional(const Bidirectional&) = default;
    EXPORT Bidirectional(Bidirectional&&) = default;
    EXPORT Bidirectional& operator=(const Bidirectional&) = default;
    EXPORT Bidirectional& operator=(Bidirectional&&) = default;

    EXPORT reference operator*()
    {
        if (nullptr == parent_) { throw std::out_of_range{""}; }

        return parent_->at(position_);
    }

    EXPORT Bidirectional& operator++()
    {
        if (std::numeric_limits<std::size_t>::max() == position_) {
            throw std::out_of_range{""};
        }

        ++position_;

        return *this;
    }
    EXPORT Bidirectional operator++(int)
    {
        Bidirectional output{*this};
        ++(*this);

        return output;
    }
    EXPORT Bidirectional& operator--()
    {
        if (std::numeric_limits<std::size_t>::min() == position_) {
            throw std::out_of_range{""};
        }

        --position_;

        return *this;
    }
    EXPORT Bidirectional operator--(int)
    {
        const auto output{Bidirectional(*this)};
        --(*this);

        return output;
    }
    EXPORT bool operator==(const Bidirectional& rhs) const
    {
        return (parent_ == rhs.parent_) && (position_ == rhs.position_);
    }
    EXPORT bool operator!=(const Bidirectional& rhs) const
    {
        return !(*this == rhs);
    }

    EXPORT ~Bidirectional() = default;

private:
    std::size_t position_{0};
    P* parent_{nullptr};
};
}  // namespace iterator
}  // namespace opentxs
#endif
