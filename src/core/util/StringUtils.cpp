// Copyright (c) 2018 The Open-Transactions developers
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

#include "stdafx.hpp"

#include "opentxs/core/util/StringUtils.hpp"

#include "opentxs/core/util/Assert.hpp"
#include "opentxs/core/util/Common.hpp"
#include "opentxs/core/String.hpp"

#ifdef ANDROID
#include <time64.h>
#endif
#include <cinttypes>
#include <cstdint>
#include <cstring>
#include <ctime>
#include <string>

#ifdef _WIN32
#include <time.h>
#include <iomanip>
#include <sstream>

extern "C" char* strptime(const char* s, const char* f, struct tm* tm)
{
    // Isn't the C++ standard lib nice? std::get_time is defined such that its
    // format parameters are the exact same as strptime. Of course, we have to
    // create a string stream first, and imbue it with the current C locale, and
    // we also have to make sure we return the right things if it fails, or
    // if it succeeds, but this is still far simpler an implementation than any
    // of the versions in any of the C standard libraries.
    std::istringstream input(s);
    input.imbue(std::locale(setlocale(LC_ALL, nullptr)));
    input >> std::get_time(tm, f);
    if (input.fail()) { return nullptr; }
    return (char*)(s + input.tellg());
}
#endif
namespace opentxs
{

// If 10 is passed in, then 11 will be allocated,
// then the data is copied, and then the result[10] (11th element)
// is set to 0. This way the original 10-length string is untouched.
//
char* str_dup2(const char* str, std::uint32_t length)  // length
                                                       // doesn't/shouldn't
// include the byte for the
// terminating 0.
{
    char* str_new = new char[length + 1];  // CREATE EXTRA BYTE OF SPACE FOR \0
                                           // (NOT PART OF LENGTH)
    OT_ASSERT(nullptr != str_new);

#ifdef _WIN32
    strncpy_s(str_new, length + 1, str, length);
#else
    strncpy(str_new, str, length);
#endif

    // INITIALIZE EXTRA BYTE OF SPACE
    //
    // If length is 10, then buffer is created with 11 elements,
    // indexed from 0 (first element) through 10 (11th element).
    //
    // Therefore str_new[length==10] is the 11th element, which was
    // the extra one created on our buffer, to store the \0 null terminator.
    //
    // This way I know I'm never cutting off data that was in the string itself.
    // Rather, I am only setting to 0 an EXTRA byte that I created myself, AFTER
    // the string's length itself.
    //
    str_new[length] = '\0';

    return str_new;
}

}  // namespace opentxs

std::string formatTimestamp(time64_t tt)
{
    char buf[255] = "";
    struct tm tm;
// -------------
#if defined(_WIN32) || defined(_WIN64)
    if (0 == _gmtime64_s(&tm, &tt)) strftime(buf, sizeof(buf), "%FT%T", &tm);
#else
    time_t t = tt;  // Todo why go backwards here? Prefer time64_t.
    strftime(buf, sizeof(buf), "%FT%T", gmtime_r(&t, &tm));
#endif
    return std::string(buf);
}

std::string formatInt(std::int32_t tt)
{
    auto temp = opentxs::String::Factory();

    temp->Format("%" PRId32 "", tt);

    return temp->Get();
}

std::string formatUint(std::uint32_t tt)
{
    auto temp = opentxs::String::Factory();

    temp->Format("%" PRIu32 "", tt);

    return temp->Get();
}

std::string formatChar(char tt)
{
    std::string temp;

    temp += tt;

    return temp;
}

std::string formatLong(std::int64_t tt)
{
    auto temp = opentxs::String::Factory();

    temp->Format("%" PRId64 "", tt);

    return temp->Get();
}

std::string formatUlong(std::uint64_t tt)
{
    auto temp = opentxs::String::Factory();

    temp->Format("%" PRIu64 "", tt);

    return temp->Get();
}

std::string formatBool(bool tt) { return tt ? "true" : "false"; }

std::string getTimestamp() { return formatTimestamp(time(NULL)); }

time64_t parseTimestamp(std::string extendedTimeString)
{
    struct tm tm;
    if (!strptime(extendedTimeString.c_str(), "%Y-%m-%dT%H:%M:%S", &tm)) {
        return 0;
    }

#ifdef ANDROID
    time64_t t = timegm64(&tm);
#else
    time_t t = timegm(&tm);
#endif
    if (t == -1) return 0;
    return t;
}
