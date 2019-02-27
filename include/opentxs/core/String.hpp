// Copyright (c) 2018 The Open-Transactions developers
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

#ifndef OPENTXS_CORE_STRING_HPP
#define OPENTXS_CORE_STRING_HPP

#include "opentxs/Forward.hpp"

#ifdef _WIN32
// support for changing between std::string and std::wstring
#include "util/win32_utf8conv.hpp"
#endif

#include <cstddef>
#include <cstdarg>
#include <cstdint>
#include <iosfwd>
#include <list>
#include <utility>
#include <string>
#include <map>
#include <vector>

#ifdef __GNUC__
#define ATTR_PRINTF(a, b) __attribute__((format(printf, a, b)))
#else
#define ATTR_PRINTF(a, b)
#endif

#ifdef _MSC_VER
#define PRI_SIZE "Iu"
#else
#define PRI_SIZE "zu"
#endif

namespace opentxs
{
class String : public Cloneable<String>
{
public:
    using List = std::list<std::string>;
    using Map = std::map<std::string, std::string>;

    EXPORT static opentxs::Pimpl<opentxs::String> Factory();
    EXPORT static opentxs::Pimpl<opentxs::String> Factory(const Armored& value);
    EXPORT static opentxs::Pimpl<opentxs::String> Factory(
        const Signature& value);
    EXPORT static opentxs::Pimpl<opentxs::String> Factory(
        const Contract& value);
    EXPORT static opentxs::Pimpl<opentxs::String> Factory(
        const Identifier& value);
    EXPORT static opentxs::Pimpl<opentxs::String> Factory(const NymFile& value);
    EXPORT static opentxs::Pimpl<opentxs::String> Factory(const char* value);
    EXPORT static opentxs::Pimpl<opentxs::String> Factory(
        const std::string& value);
    EXPORT static opentxs::Pimpl<opentxs::String> Factory(
        const char* value,
        std::size_t size);

    EXPORT static std::string LongToString(const std::int64_t& lNumber);
    EXPORT static std::string replace_chars(
        const std::string& str,
        const std::string& charsFrom,
        const char& charTo);
#ifdef _WIN32
    EXPORT static std::wstring s2ws(const std::string& s);
#endif
    EXPORT static std::size_t safe_strlen(const char* s, std::size_t max);
    EXPORT static std::int32_t StringToInt(const std::string& number);
    EXPORT static std::int64_t StringToLong(const std::string& number);
    EXPORT static std::uint32_t StringToUint(const std::string& number);
    EXPORT static std::uint64_t StringToUlong(const std::string& number);
    EXPORT static std::string& trim(std::string& str);
    EXPORT static std::string UlongToString(const std::uint64_t& uNumber);
    EXPORT static bool vformat(
        const char* fmt,
        std::va_list* pvl,
        std::string& s) ATTR_PRINTF(1, 0);
#ifdef _WIN32
    EXPORT static std::string ws2s(const std::wstring& s);
#endif

    EXPORT virtual bool operator>(const String& rhs) const = 0;
    EXPORT virtual bool operator<(const String& rhs) const = 0;
    EXPORT virtual bool operator<=(const String& rhs) const = 0;
    EXPORT virtual bool operator>=(const String& rhs) const = 0;
    EXPORT virtual bool operator==(const String& rhs) const = 0;

    EXPORT virtual bool At(std::uint32_t index, char& c) const = 0;
    EXPORT virtual bool Compare(const char* compare) const = 0;
    EXPORT virtual bool Compare(const String& compare) const = 0;
    EXPORT virtual bool Contains(const char* compare) const = 0;
    EXPORT virtual bool Contains(const String& compare) const = 0;
    EXPORT virtual bool empty() const = 0;
    EXPORT virtual bool Exists() const = 0;
    EXPORT virtual const char* Get() const = 0;
    EXPORT virtual std::uint32_t GetLength() const = 0;
    EXPORT virtual std::int32_t ToInt() const = 0;
    EXPORT virtual bool TokenizeIntoKeyValuePairs(Map& map) const = 0;
    EXPORT virtual std::int64_t ToLong() const = 0;
    EXPORT virtual std::uint32_t ToUint() const = 0;
    EXPORT virtual std::uint64_t ToUlong() const = 0;
    EXPORT virtual void WriteToFile(std::ostream& ofs) const = 0;

    EXPORT virtual void Concatenate(const char* arg, ...) ATTR_PRINTF(2, 3) = 0;
    EXPORT virtual void Concatenate(const String& data) = 0;
    EXPORT virtual void ConvertToUpperCase() = 0;
    EXPORT virtual bool DecodeIfArmored(bool escapedIsAllowed = true) = 0;
    EXPORT virtual void Format(const char* fmt, ...) ATTR_PRINTF(2, 3) = 0;
    /** For a straight-across, exact-size copy of bytes. Source not expected to
     * be null-terminated. */
    EXPORT virtual bool MemSet(const char* mem, std::uint32_t size) = 0;
    EXPORT virtual void Release() = 0;
    /** new_string MUST be at least nEnforcedMaxLength in size if
    nEnforcedMaxLength is passed in at all.
    That's because this function forces the null terminator at that length,
    minus 1. For example, if the max is set to 10, then the valid range is 0..9.
    Therefore 9 (10 minus 1) is where the nullptr terminator goes. */
    EXPORT virtual void Set(
        const char* data,
        std::uint32_t enforcedMaxLength = 0) = 0;
    EXPORT virtual void Set(const String& data) = 0;
    /** true  == there are more lines to read.
    false == this is the last line. Like EOF. */
    EXPORT virtual bool sgets(char* buffer, std::uint32_t size) = 0;
    EXPORT virtual char sgetc() = 0;
    EXPORT virtual void swap(String& rhs) = 0;
    EXPORT virtual void reset() = 0;

    EXPORT virtual ~String() = default;

protected:
    String() = default;

private:
    friend OTString;
    friend std::ostream& operator<<(std::ostream& os, const String& obj);

    //virtual String* clone() const = 0;

    String(String&& rhs) = delete;
    String& operator=(const String& rhs) = delete;
    String& operator=(String&& rhs) = delete;
};
}  // namespace opentxs
#endif
