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
 * TODO TSB
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
     * TODO TSB
     */
    bool hasErrorCode() const;

    /**
     * TODO TSB
     */
    NativeErrorCodeType getErrorCode() const;

private:
    NativeErrorCodeType mErrorCode;
};

}

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

#endif

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
