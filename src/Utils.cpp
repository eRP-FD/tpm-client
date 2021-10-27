/*
 * (C) Copyright IBM Deutschland GmbH 2021
 * (C) Copyright IBM Corp. 2021
 * SPDX-License-Identifier: CC BY-NC-ND 3.0 DE
 */

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

#include "Utils.h"

#include "Exception.h"

#include <ibmtss/tssresponsecode.h>

#include <climits>

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

namespace
{
    constexpr const char TSS_ERROR_PREFIX[] = "internal TSS error description";
    constexpr const char TSS_ERROR_SEPARATOR[] = " -- ";

    void AppendErrorIfNotEmpty(std::string& result, const char* error)
    {
        if (error)
        {
            std::string errorString{error};
            if (!errorString.empty())
            {
                result += TSS_ERROR_SEPARATOR + errorString;
            }
        }
    }
}

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

std::string tpmclient::Utils::BuildErrorMessage(Exception::NativeErrorCodeType errorCode)
{
    if (errorCode == Exception::INVALID_ERROR_CODE)
    {
        throw Exception{"Unable to build TSS error message: given error code is not erroneous"};
    }

    const char* errorMessage{};
    const char* errorDescription{};
    const char* errorNumber{};

    TSS_ResponseCode_toString(&errorMessage, &errorDescription, &errorNumber, errorCode);

    std::string result{TSS_ERROR_PREFIX};
    AppendErrorIfNotEmpty(result, errorMessage);
    AppendErrorIfNotEmpty(result, errorDescription);
    AppendErrorIfNotEmpty(result, errorNumber);

    return result;
}

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

std::uint8_t tpmclient::Utils::GetNthByte(std::uint64_t input, std::size_t index)
{
    if (index > CHAR_BIT)
    {
        throw Exception{"Unable to get n-th byte: index larger than CHAR_BIT"};
    }

    return (input >> ((index - 1) << 3)) & 0xff;
}

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
