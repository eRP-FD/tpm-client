/*
 * (C) Copyright IBM Deutschland GmbH 2021
 * (C) Copyright IBM Corp. 2021
 * SPDX-License-Identifier: CC BY-NC-ND 3.0 DE
 */

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

#ifndef TPM_CLIENT_EXCEPTION_H
#define TPM_CLIENT_EXCEPTION_H

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

#include <cstdint>
#include <stdexcept>
#include <string>

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

namespace tpmclient
{

/**
 * Base exception class thrown by all tpmclient API calls.
 */
class Exception : public std::runtime_error
{
public:
    using NativeErrorCodeType = std::uint32_t;

    static constexpr const NativeErrorCodeType INVALID_ERROR_CODE = 0;

    Exception();

    explicit Exception(const std::string& errorMessage);

    explicit Exception(NativeErrorCodeType errorCode);

    Exception(const std::string& errorMessage, NativeErrorCodeType errorCode);

    /**
     * Checks if the exception object has an associated error code.
     */
    bool hasErrorCode() const;

    /**
     * Returns the error code (presumably from the underlying TSS library).
     */
    NativeErrorCodeType getErrorCode() const;

private:
    NativeErrorCodeType mErrorCode;
};

}

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

#endif

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
