#include "Client.h"

#include "Exception.h"
#include "Session.h"

#include <gtest/gtest.h>

#include <memory>
#include <utility>

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

namespace
{
    tpmclient::Client GetClient()
    {
        auto session = std::make_shared<tpmclient::Session>();
        session->open();

        return tpmclient::Client{std::move(session)};
    }
}

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

TEST(ClientTests, lifetime)
{
    EXPECT_NO_THROW({ tpmclient::Client{}; });
    EXPECT_NO_THROW({ tpmclient::Client{std::make_shared<tpmclient::Session>()}; });
}

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

TEST(ClientTests, hasSession)
{
    tpmclient::Client client{};

    EXPECT_FALSE(client.hasSession());
    EXPECT_THROW(client.getSession(), tpmclient::Exception);

    client = GetClient();

    EXPECT_TRUE(client.hasSession());
    EXPECT_NO_THROW(client.getSession());
}

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

TEST(ClientTests, setSession)
{
    tpmclient::Client client{};
    const auto session = std::make_shared<tpmclient::Session>();

    client.setSession(session);
    EXPECT_EQ(&client.getSession(), session.get());
}

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

TEST(ClientTests, isValid)
{
    tpmclient::Client client{};

    EXPECT_FALSE(client.isValid());

    auto session = std::make_shared<tpmclient::Session>();
    client.setSession(session);

    EXPECT_FALSE(client.isValid());

    session->open();

    EXPECT_TRUE(client.isValid());
}

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

TEST(ClientTests, ping)
{
    const auto client = GetClient();

    EXPECT_NO_THROW(client.ping());
}

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

TEST(ClientTests, getEk)
{
    const auto client = GetClient();

    const auto endorsementIdentity = client.getEk();
    EXPECT_FALSE(endorsementIdentity.keyName.empty());
    EXPECT_FALSE(endorsementIdentity.certificate.empty());
}

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

TEST(ClientTests, createAk)
{
    const auto client = GetClient();

    const auto akBlob = client.createAk();
    EXPECT_FALSE(akBlob.empty());
}

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

TEST(ClientTests, getAk)
{
    const auto akBlob = GetClient().createAk();

    const auto ak = GetClient().getAk(akBlob);
    EXPECT_FALSE(ak.name.empty());
    EXPECT_FALSE(ak.key.empty());
}

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

TEST(ClientTests, makeCredential)
{
    const auto akBlob = GetClient().createAk();

    const auto madeCredential = GetClient().makeCredential(akBlob);
    EXPECT_FALSE(madeCredential.secret.empty());
    EXPECT_FALSE(madeCredential.credential.empty());
    EXPECT_FALSE(madeCredential.encryptedCredential.empty());
}

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

TEST(ClientTests, authenticateCredential)
{
    const auto akBlob = GetClient().createAk();
    const auto madeCredential = GetClient().makeCredential(akBlob);

    const auto decryptedCredential = GetClient().authenticateCredential(
                                                           tpmclient::GetBufferView(madeCredential.secret),
                                                           tpmclient::GetBufferView(madeCredential.encryptedCredential),
                                                           akBlob);

    EXPECT_EQ(madeCredential.credential, decryptedCredential);
}

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

TEST(ClientTests, getQuote)
{
    const auto akBlob = GetClient().createAk();

    const auto quote = GetClient().getQuote(tpmclient::GetBufferView(tpmclient::Buffer(32, 0xca)),
                                            tpmclient::PCRRegisterList{0},
                                            akBlob);

    EXPECT_FALSE(quote.data.empty());
    EXPECT_FALSE(quote.signature.empty());
}

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

TEST(ClientTests, verifyQuote)
{
    const auto akBlob = GetClient().createAk();

    auto quote = GetClient().getQuote(tpmclient::GetBufferView(tpmclient::Buffer(32, 0xca)),
                                      tpmclient::PCRRegisterList{0},
                                      akBlob);

    EXPECT_NO_THROW(GetClient().verifyQuote(quote, akBlob));
    ASSERT_FALSE(quote.signature.empty());

    quote.signature.front() = 0xca;
    EXPECT_THROW(GetClient().verifyQuote(quote, akBlob), tpmclient::Exception);
}

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
