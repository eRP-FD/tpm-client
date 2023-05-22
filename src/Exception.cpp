/*
 * (C) Copyright IBM Deutschland GmbH 2021, 2023
 * (C) Copyright IBM Corp 2021, 2023
 *
 * non-exclusively licensed to gematik GmbH
 */

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

#include "Exception.h"

#include "Utils.h"

#include <ibmtss/TPM_Types.h>

#include <type_traits>

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

namespace
{
    constexpr const char DEFAULT_ERROR_MESSAGE[] = "no error message specified";
}

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

tpmclient::Exception::Exception()
: Exception{DEFAULT_ERROR_MESSAGE}
{
    static_assert(std::is_same_v<NativeErrorCodeType, TPM_RC>);
}

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

tpmclient::Exception::Exception(const std::string& errorMessage)
: std::runtime_error{errorMessage.c_str()},
  mErrorCode{INVALID_ERROR_CODE}
{

}

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

tpmclient::Exception::Exception(NativeErrorCodeType errorCode)
: Exception{Utils::BuildErrorMessage(errorCode), errorCode}
{

}

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

tpmclient::Exception::Exception(const std::string& errorMessage, NativeErrorCodeType errorCode)
: std::runtime_error{errorMessage.c_str()},
  mErrorCode{errorCode}
{

}

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

bool tpmclient::Exception::hasErrorCode() const
{
    return mErrorCode != INVALID_ERROR_CODE;
}

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

tpmclient::Exception::NativeErrorCodeType tpmclient::Exception::getErrorCode() const
{
    return mErrorCode;
}

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
