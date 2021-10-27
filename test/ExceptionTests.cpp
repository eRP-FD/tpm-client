/*
 * (C) Copyright IBM Deutschland GmbH 2021
 * (C) Copyright IBM Corp. 2021
 * SPDX-License-Identifier: CC BY-NC-ND 3.0 DE
 */

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

#include "Exception.h"

#include <gtest/gtest.h>

#include <cstdint>
#include <string>

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

namespace
{
    constexpr const char CUSTOM_ERROR_MESSAGE[] = "custom error message";

    constexpr const std::uint32_t CUSTOM_ERROR_CODE = 1;
}

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

TEST(ExceptionTests, lifetime)
{
    EXPECT_NO_THROW({ tpmclient::Exception{}; });
    EXPECT_NO_THROW({ tpmclient::Exception{""}; });
    EXPECT_NO_THROW({ tpmclient::Exception{CUSTOM_ERROR_CODE}; });
    EXPECT_NO_THROW({ tpmclient::Exception("", CUSTOM_ERROR_CODE); });
}

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

TEST(ExceptionTests, construct_default)
{
    tpmclient::Exception exception{};

    EXPECT_EQ(exception.what(), std::string{"no error message specified"});

    EXPECT_FALSE(exception.hasErrorCode());
}

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

TEST(ExceptionTests, constructs_withErrorMessage)
{
    const std::string errorMessage{CUSTOM_ERROR_MESSAGE};

    tpmclient::Exception exception{errorMessage};

    EXPECT_EQ(exception.what(), errorMessage);

    EXPECT_FALSE(exception.hasErrorCode());
}

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

TEST(ExceptionTests, construct_withErrorCode)
{
    tpmclient::Exception exception{CUSTOM_ERROR_CODE};

    EXPECT_NE(exception.what(), nullptr);
    EXPECT_NE(exception.what(), std::string{});

    EXPECT_TRUE(exception.hasErrorCode());
    EXPECT_EQ(exception.getErrorCode(), CUSTOM_ERROR_CODE);
}

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

TEST(ExceptionTests, construct_withBothErrorMessageAndCode)
{
    const std::string errorMessage{CUSTOM_ERROR_MESSAGE};

    tpmclient::Exception exception{errorMessage, CUSTOM_ERROR_CODE};

    EXPECT_EQ(exception.what(), errorMessage);

    EXPECT_TRUE(exception.hasErrorCode());
    EXPECT_EQ(exception.getErrorCode(), CUSTOM_ERROR_CODE);
}

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
