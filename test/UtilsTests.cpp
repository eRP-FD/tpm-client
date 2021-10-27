/*
 * (C) Copyright IBM Deutschland GmbH 2021
 * (C) Copyright IBM Corp. 2021
 * SPDX-License-Identifier: CC BY-NC-ND 3.0 DE
 */

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

#include "Utils.h"

#include "Exception.h"

#include <ibmtss/tsserror.h>

#include <gtest/gtest.h>

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

TEST(UtilsTests, buildErrorMessage)
{
    EXPECT_EQ(tpmclient::Utils::BuildErrorMessage(TSS_RC_NO_CONNECTION),
              std::string{"internal TSS error description -- TSS_RC_NO_CONNECTION - "
                          "Failure connecting to lower layer"});

    EXPECT_EQ(tpmclient::Utils::BuildErrorMessage(TSS_RC_BAD_CONNECTION),
              std::string{"internal TSS error description -- TSS_RC_BAD_CONNECTION - "
                          "Failure communicating with lower layer"});

    EXPECT_EQ(tpmclient::Utils::BuildErrorMessage(TSS_RC_FAIL),
              std::string{"internal TSS error description -- TSS_RC_FAIL - TSS internal failure"});
}

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

TEST(UtilsTests, buildErrorMessage_invalidErrorCode)
{
    EXPECT_THROW(tpmclient::Utils::BuildErrorMessage(tpmclient::Exception::INVALID_ERROR_CODE), tpmclient::Exception);
}

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

TEST(UtilsTests, tryCatchFixRetry)
{
    EXPECT_NO_THROW(tpmclient::Utils::TryCatchFixRetry([]()
                                                      {
                                                          // try a successful operation
                                                          //
                                                          return true;
                                                      },
                                                      [](const auto&) -> bool
                                                      {
                                                          // no catching should be needed
                                                          //
                                                          EXPECT_TRUE(false);
                                                          return false;
                                                      },
                                                      []()
                                                      {
                                                          // and no fixing neither
                                                          //
                                                          FAIL();
                                                      }));

    bool shouldFail = true;
    bool catchConditionCalled = false;
    bool fixOperationCalled = false;

    EXPECT_NO_THROW(tpmclient::Utils::TryCatchFixRetry([&shouldFail]()
                                                       {
                                                           if (shouldFail)
                                                           {
                                                               throw tpmclient::Exception{};
                                                           }

                                                           return true;
                                                       },
                                                       [&shouldFail, &catchConditionCalled](const auto&) -> bool
                                                       {
                                                           EXPECT_TRUE(shouldFail);
                                                           catchConditionCalled = true;
                                                           return true;
                                                       },
                                                       [&shouldFail, &fixOperationCalled]()
                                                       {
                                                           EXPECT_TRUE(shouldFail);
                                                           fixOperationCalled = true;
                                                           shouldFail = false;
                                                       }));

    EXPECT_FALSE(shouldFail);
    EXPECT_TRUE(catchConditionCalled);
    EXPECT_TRUE(fixOperationCalled);
}

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

TEST(UtilsTests, tryCatchFixRetry_fixDoesNotWork)
{
    bool catchConditionCalled = false;
    bool fixOperationCalled = false;

    EXPECT_THROW(tpmclient::Utils::TryCatchFixRetry([]()
                                                    {
                                                        throw tpmclient::Exception{};
                                                    },
                                                    [&catchConditionCalled](const auto&) -> bool
                                                    {
                                                        EXPECT_FALSE(catchConditionCalled);
                                                        catchConditionCalled = true;
                                                        return true;
                                                    },
                                                    [&fixOperationCalled]()
                                                    {
                                                        EXPECT_FALSE(fixOperationCalled);
                                                        fixOperationCalled = true;
                                                    }),
                 tpmclient::Exception);

    EXPECT_TRUE(catchConditionCalled);
    EXPECT_TRUE(fixOperationCalled);
}


////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

TEST(UtilsTests, tryCatchFixRetry_catchDoesNotMatch)
{
    bool catchConditionCalled = false;

    EXPECT_THROW(tpmclient::Utils::TryCatchFixRetry([]()
                                                    {
                                                        throw tpmclient::Exception{};
                                                    },
                                                    [&catchConditionCalled](const auto&) -> bool
                                                    {
                                                        EXPECT_FALSE(catchConditionCalled);
                                                        catchConditionCalled = true;
                                                        return false;
                                                    },
                                                    []()
                                                    {
                                                        FAIL();
                                                    }),
                 tpmclient::Exception);

    EXPECT_TRUE(catchConditionCalled);
}

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
