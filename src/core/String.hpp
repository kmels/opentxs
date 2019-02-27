// Copyright (c) 2018 The Open-Transactions developers
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

#pragma once

#include "Internal.hpp"

#include "opentxs/core/String.hpp"

namespace opentxs::implementation
{
class String : virtual public opentxs::String, public virtual IClonable
{
public:
    bool operator>(const opentxs::String& rhs) const override;
    bool operator<(const opentxs::String& rhs) const override;
    bool operator<=(const opentxs::String& rhs) const override;
    bool operator>=(const opentxs::String& rhs) const override;
    bool operator==(const opentxs::String& rhs) const override;

    bool At(std::uint32_t index, char& c) const override;
    bool Compare(const char* compare) const override;
    bool Compare(const opentxs::String& compare) const override;
    bool Contains(const char* compare) const override;
    bool Contains(const opentxs::String& compare) const override;
    bool empty() const override;
    bool Exists() const override;
    const char* Get() const override;
    std::uint32_t GetLength() const override;
    std::int32_t ToInt() const override;
    bool TokenizeIntoKeyValuePairs(Map& map) const override;
    std::int64_t ToLong() const override;
    std::uint32_t ToUint() const override;
    std::uint64_t ToUlong() const override;
    void WriteToFile(std::ostream& ofs) const override;

    void Concatenate(const char* arg, ...) override;
    void Concatenate(const opentxs::String& data) override;
    void ConvertToUpperCase() override;
    bool DecodeIfArmored(bool escapedIsAllowed = true) override;
    void Format(const char* fmt, ...) override;
    /** For a straight-across, exact-size copy of bytes. Source not expected to
     * be null-terminated. */
    bool MemSet(const char* mem, std::uint32_t size) override;
    void Release() override;
    /** new_string MUST be at least nEnforcedMaxLength in size if
    nEnforcedMaxLength is passed in at all.
    That's because this function forces the null terminator at that length,
    minus 1. For example, if the max is set to 10, then the valid range is 0..9.
    Therefore 9 (10 minus 1) is where the nullptr terminator goes. */
    void Set(const char* data, std::uint32_t enforcedMaxLength = 0) override;
    void Set(const opentxs::String& data) override;
    /** true  == there are more lines to read.
    false == this is the last line. Like EOF. */
    bool sgets(char* buffer, std::uint32_t size) override;
    char sgetc() override;
    void swap(opentxs::String& rhs) override;
    void reset() override;

    ~String();

protected:
    virtual void Release_String();

    explicit String(const Armored& value);
    explicit String(const Signature& value);
    explicit String(const Contract& value);
    explicit String(const Identifier& value);
    explicit String(const NymFile& value);
    String(const char* value);
    explicit String(const std::string& value);
    String(const char* value, std::size_t size);
    String& operator=(const String& rhs);
    String();
    String(const String& rhs);

private:
    friend opentxs::String;

    static const std::string empty_;

    std::uint32_t length_{0};
    std::uint32_t position_{0};
    std::vector<char> internal_{};

    static std::vector<char> make_string(const char* str, std::uint32_t length);

	IClonable* CloneImpl() const override;
    //String* clone() const override;
    
	/** Only call this right after calling Initialize() or Release(). Also, this
     * function ASSUMES the new_string pointer is good. */
    void LowLevelSet(const char* data, std::uint32_t enforcedMaxLength);
    /** You better have called Initialize() or Release() before you dare call
     * this. */
    void LowLevelSetStr(const String& buffer);

    void Initialize();
    void zeroMemory();
};
}  // namespace opentxs::implementation
