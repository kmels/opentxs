// Copyright (c) 2018 The Open-Transactions developers
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

#pragma once

#include "Internal.hpp"

namespace opentxs::implementation
{
class Data : virtual public opentxs::Data, virtual public IClonable
{
public:
    bool operator==(const opentxs::Data& rhs) const override;
    bool operator!=(const opentxs::Data& rhs) const override;
    Data& operator+=(const opentxs::Data& rhs) override;

    std::string asHex() const override;
    const std::byte& at(const std::size_t position) const override
    {
        return reinterpret_cast<const std::byte&>(data_.at(position));
    }
    const_iterator begin() const override { return const_iterator(this, 0); }
    const_iterator cbegin() const override { return const_iterator(this, 0); }
    const_iterator cend() const override
    {
        return const_iterator(this, data_.size());
    }
    bool empty() const override { return data_.empty(); }
    const void* data() const override { return data_.data(); }
    const_iterator end() const override
    {
        return const_iterator(this, data_.size());
    }
    bool IsEmpty() const override { return empty(); }
    const void* GetPointer() const override { return data_.data(); }
    std::size_t GetSize() const override { return size(); }
    std::size_t size() const override { return data_.size(); }

    void Assign(const opentxs::Data& source) override;
    void Assign(const void* data, const std::size_t& size) override;
    std::byte& at(const std::size_t position) override
    {
        return reinterpret_cast<std::byte&>(data_.at(position));
    }
    iterator begin() override { return iterator(this, 0); }
    void Concatenate(const void* data, const std::size_t& size) override;
    void* data() override { return data_.data(); }
    iterator end() override { return iterator(this, data_.size()); }
    std::size_t OTfread(std::uint8_t* data, const std::size_t& size) override;
    bool Randomize(const std::size_t& size) override;
    void Release() override;
    void reset() override { position_ = 0; }
    void SetSize(const std::size_t& size) override;
    void swap(opentxs::Data&& rhs) override;
    void zeroMemory() override;

    virtual ~Data() = default;

protected:
    using Vector = std::vector<std::uint8_t>;

    Vector data_{};
    std::size_t position_{0};

    void Initialize();

    Data() = default;
    explicit Data(const void* data, std::size_t size);
    explicit Data(const Armored& source);
    explicit Data(const std::vector<unsigned char>& sourceVector);
    explicit Data(const Vector& rhs, const std::size_t size);

private:
    friend opentxs::Data;

	//IClonable* CloneImpl(void) const override;

	IClonable* CloneImpl() const override {return new Data(this->data_, this->position_); }

    //Data* clone() const override
    //{
    //    return new Data(this->data_, this->position_);
    //}

    void concatenate(const Vector& data);

    Data(const Data& rhs) = delete;
    Data(Data&& rhs) = delete;
    Data& operator=(const Data& rhs) = delete;
    Data& operator=(Data&& rhs) = delete;
};
}  // namespace opentxs::implementation
