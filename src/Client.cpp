/*
 * (C) Copyright IBM Deutschland GmbH 2021
 * (C) Copyright IBM Corp. 2021
 * SPDX-License-Identifier: CC BY-NC-ND 3.0 DE
 */

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

#include "Client.h"

#include "ClientUser.h"
#include "Exception.h"
#include "Session.h"
#include "StorageIndex.h"
#include "StorageIndexMap.h"
#include "ScratchPad.h"
#include "Utils.h"

#include <ibmtss/tss.h>
#include <ibmtss/tssmarshal.h>

#include <arpa/inet.h>

#include <algorithm>
#include <array>
#include <cstdlib>
#include <cstring>
#include <functional>
#include <utility>

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

namespace
{
    using X509Ptr = std::unique_ptr<X509, decltype(&X509_free)>;

    struct TpmtKeyPair
    {
        TpmtKeyPair()
        : privatePart{},
          publicPart{std::make_unique<TPM2B_PUBLIC>()}
        {

        }

        TpmtKeyPair(TPM2B_PRIVATE privatePartArg, TPM2B_PUBLIC publicPartArg)
        : TpmtKeyPair{}
        {
            privatePart = std::move(privatePartArg);
            *publicPart = std::move(publicPartArg);
        }

        TPM2B_PRIVATE privatePart;
        std::unique_ptr<TPM2B_PUBLIC> publicPart;
    };

    constexpr const std::size_t DEFAULT_DATA_MTU = 512;
    constexpr const std::size_t CREDENTIAL_SIZE = 32;
    constexpr const std::size_t MAX_VALUE_PCR_REGISTER = 23;

    constexpr const std::size_t PK_POLICY_SIZE = 32;
    constexpr const std::array<unsigned char, PK_POLICY_SIZE> PK_POLICY{};

    constexpr const std::size_t AK_POLICY_SIZE = 32;
    constexpr const std::array<unsigned char, AK_POLICY_SIZE> AK_POLICY{0xe5, 0x87, 0xc1, 0x1a, 0xb5, 0x0f, 0x9d, 0x87,
                                                                        0x30, 0xf7, 0x21, 0xe3, 0xfe, 0xa4, 0x2b, 0x46,
                                                                        0xc0, 0x45, 0x5b, 0x24, 0x6f, 0x96, 0xae, 0xe8,
                                                                        0x5d, 0x18, 0xeb, 0x3b, 0xe6, 0x4d, 0x66, 0x6a};

    bool IsSoftwareTpm()
    {
        const auto* interfaceType = std::getenv("TPM_INTERFACE_TYPE");
        return interfaceType && std::string{interfaceType} == "socsim";
    }

    tpmclient::Buffer truncateCertificate(const tpmclient::BufferView& certificate)
    {
        using namespace tpmclient;

        const auto* certificateBuffer = certificate.data();
        X509Ptr x509{d2i_X509(nullptr, &certificateBuffer, certificate.size()), &X509_free};
        if (!x509)
        {
            throw Exception{"Unable to truncate certificate: cannot parse it"};
        }

        Buffer::value_type* resultBuffer{};
        const auto resultBufferSize = i2d_X509(x509.get(), &resultBuffer);
        if (resultBufferSize <= 0)
        {
            throw Exception{"Unable to truncate certificate: cannot serialize it"};
        }

        Buffer result(resultBufferSize);
        static_cast<void>(std::move(resultBuffer,
                                    resultBuffer + resultBufferSize,
                                    result.begin()));
        OPENSSL_free(resultBuffer);

        return result;
    }

    template <typename DeserializationFunctionT>
    auto getGenericDeserializationFunction(const DeserializationFunctionT& deserializationFunction)
    {
        return std::bind(deserializationFunction,
                         std::placeholders::_1,
                         std::placeholders::_2,
                         std::placeholders::_3,
                         false);
    }

    template <typename ObjectT, typename SerializationFunctionT>
    tpmclient::Buffer serializeTssObject(const ObjectT& object, const SerializationFunctionT& serializationFunction)
    {
        using namespace tpmclient;

        Buffer::value_type* buffer{};
        std::uint16_t bufferSize{};
        const auto serializationResult = TSS_Structure_Marshal(
                                                            &buffer,
                                                            &bufferSize,
                                                            &const_cast<ObjectT&>(object),
                                                            reinterpret_cast<MarshalFunction_t>(serializationFunction));

        if (serializationResult)
        {
            throw Exception{"Unable to serialize TSS object: " + Utils::BuildErrorMessage(serializationResult),
                            serializationResult};
        }

        Buffer result(bufferSize);
        static_cast<void>(std::move(buffer, buffer + bufferSize, result.begin()));
        std::free(buffer);

        return result;
    }

    tpmclient::Buffer serializeTpmtKeyPair(const TpmtKeyPair& keyPair)
    {
        using namespace tpmclient;

        auto serializedPrivatePart = serializeTssObject(keyPair.privatePart, TSS_TPM2B_PRIVATE_Marshalu);
        const auto serializedPrivatePartSize = htons(serializedPrivatePart.size());
        auto serializedPublicPart = serializeTssObject(*keyPair.publicPart, TSS_TPM2B_PUBLIC_Marshalu);
        const auto serializedPublicPartSize = htons(serializedPublicPart.size());

        return Utils::ConcatenateBuffers(Buffer{Utils::GetNthByte(serializedPrivatePartSize, 1)},
                                         Buffer{Utils::GetNthByte(serializedPrivatePartSize, 2)},
                                         std::move(serializedPrivatePart),
                                         Buffer{Utils::GetNthByte(serializedPublicPartSize, 1)},
                                         Buffer{Utils::GetNthByte(serializedPublicPartSize, 2)},
                                         std::move(serializedPublicPart));
    }

    template <typename ObjectT, typename DeserializationFunctionT>
    void deserializeTssObject(ObjectT& object,
                              const tpmclient::BufferView& buffer,
                              const DeserializationFunctionT& deserializationFunction)
    {
        using namespace tpmclient;

        auto* rawBuffer = buffer.data();
        std::uint32_t rawBufferSize = buffer.size();

        const auto deserializationResult = deserializationFunction(&object,
                                                                   const_cast<Buffer::value_type**>(&rawBuffer),
                                                                   &rawBufferSize);

        if (deserializationResult)
        {
            throw Exception{"Unable to deserialize TSS object: " + Utils::BuildErrorMessage(deserializationResult),
                            deserializationResult};
        }
    }

    TpmtKeyPair deserializeTpmtKeyPair(const tpmclient::BufferView& buffer)
    {
        using namespace tpmclient;

        auto* rawBuffer = buffer.data();
        std::size_t nextChunkSize{};
        std::size_t minimumRawBufferSize{};

        const auto moveToNextChunk = [&](std::size_t nextChunkSizeArg)
        {
            minimumRawBufferSize += nextChunkSizeArg;
            if (buffer.size() < minimumRawBufferSize)
            {
                throw Exception{"Unable to deserialize TPMT key pair: buffer size too small"};
            }

            rawBuffer += nextChunkSize;
            nextChunkSize = nextChunkSizeArg;
        };

        const auto deserializeNextChunkSize = [&]()
        {
            moveToNextChunk(sizeof(std::uint16_t));
            std::uint16_t deserializedNextChunkSize{};
            std::memcpy(&deserializedNextChunkSize, rawBuffer, nextChunkSize);
            return ntohs(deserializedNextChunkSize);
        };

        TpmtKeyPair result{};

        moveToNextChunk(deserializeNextChunkSize());
        deserializeTssObject(result.privatePart, BufferView(rawBuffer, nextChunkSize), TSS_TPM2B_PRIVATE_Unmarshalu);

        moveToNextChunk(deserializeNextChunkSize());
        deserializeTssObject(*result.publicPart,
                             BufferView(rawBuffer, nextChunkSize),
                             getGenericDeserializationFunction(TSS_TPM2B_PUBLIC_Unmarshalu));

        moveToNextChunk(0);
        if (rawBuffer != buffer.cend())
        {
            throw Exception{"Unable to deserialize TPMT key pair: wrong buffer size"};
        }

        return result;
    }
}

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

tpmclient::Client::Client()
: mSession{},
  mPkHandle{},
  mAkHandle{},
  mEkHandle{},
  mDataMtu{}
{
    static_assert(std::is_same_v<decltype(mPkHandle), TPM_HANDLE>);
}

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

tpmclient::Client::Client(std::shared_ptr<Session> session)
: Client{}
{
    mSession = std::move(session);
}

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

void tpmclient::Client::setSession(std::shared_ptr<Session> session)
{
    mSession = std::move(session);
}

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

bool tpmclient::Client::hasSession() const
{
    return mSession != nullptr;
}

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

const tpmclient::Session& tpmclient::Client::getSession() const
{
    if (!hasSession())
    {
        throw Exception{"Unable to get session: client does not have one"};
    }

    return *mSession;
}

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

bool tpmclient::Client::isValid() const
{
    return hasSession() && mSession->isOpen();
}

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

void tpmclient::Client::ping() const
{
    ensureIsValid();

    Utils::TryCatchFixRetry([this]()
                            {
                                GetTestResult_Out out{};
                                const auto commandResult = TSS_Execute(mSession->getNative(),
                                                                       reinterpret_cast<RESPONSE_PARAMETERS*>(&out),
                                                                       nullptr,
                                                                       nullptr,
                                                                       TPM_CC_GetTestResult,
                                                                       TPM_RH_NULL,
                                                                       nullptr,
                                                                       0);

                                if (commandResult || out.testResult)
                                {
                                    const auto errorCode = commandResult ? commandResult : out.testResult;
                                    throw Exception{"Unable to ping: " + Utils::BuildErrorMessage(errorCode),
                                                    errorCode};
                                }
                            },
                            [](const auto& ex)
                            {
                                return ex.getErrorCode() == TPM_RC_INITIALIZE;
                            },
                            [this]()
                            {
                                initialize();
                            });
}

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

tpmclient::EndorsementIdentity tpmclient::Client::getEk() const
{
    ClientUser clientUser{*this};

    EndorsementIdentity result{};

    bool ekNameGotten = false;
    const auto getEkName = [&result, &ekNameGotten, this](bool withCertificate)
    {
        createEk(withCertificate);
        result.keyName = std::move(retrievePublicKey(mEkHandle).name);
        ekNameGotten = true;
    };

    result.certificate = Utils::TryCatchFixRetry([this]()
                                                {
                                                    return truncateCertificate(GetBufferView(
                                                               retrieveData(StorageIndexMap::GetInstance().getIndex(
                                                                    StorageIndexKey::PredefinedKeys::EK_CERTIFICATE))));
                                                },
                                                [](const auto& ex)
                                                {
                                                    return (ex.getErrorCode() & 0xff) == TPM_RC_HANDLE;
                                                },
                                                [&getEkName]()
                                                {
                                                    getEkName(true);
                                                });

    if (!ekNameGotten)
    {
        getEkName(false);
    }

    return result;
}

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

tpmclient::KeyPairBlob tpmclient::Client::createAk() const
{
    ClientUser clientUser{*this};

    createPk();

    Create_In input{};
    input.parentHandle = mPkHandle;

    input.inPublic.publicArea.type = TPM_ALG_ECC;
    input.inPublic.publicArea.nameAlg = TPM_ALG_SHA256;

    input.inPublic.publicArea.objectAttributes.val |= TPMA_OBJECT_NODA;
    input.inPublic.publicArea.objectAttributes.val |= TPMA_OBJECT_FIXEDTPM;
    input.inPublic.publicArea.objectAttributes.val |= TPMA_OBJECT_FIXEDPARENT;
    input.inPublic.publicArea.objectAttributes.val |= TPMA_OBJECT_SENSITIVEDATAORIGIN;
    input.inPublic.publicArea.objectAttributes.val |= TPMA_OBJECT_USERWITHAUTH;
    input.inPublic.publicArea.objectAttributes.val &= ~TPMA_OBJECT_ADMINWITHPOLICY;
    input.inPublic.publicArea.objectAttributes.val |= TPMA_OBJECT_SIGN;
    input.inPublic.publicArea.objectAttributes.val &= ~TPMA_OBJECT_DECRYPT;
    input.inPublic.publicArea.objectAttributes.val |= TPMA_OBJECT_RESTRICTED;
    input.inPublic.publicArea.objectAttributes.val &= ~0;

    input.inPublic.publicArea.parameters.eccDetail.symmetric.algorithm = TPM_ALG_NULL;
    input.inPublic.publicArea.parameters.eccDetail.scheme.scheme = TPM_ALG_ECDSA;
    input.inPublic.publicArea.parameters.eccDetail.scheme.details.ecdsa.hashAlg = TPM_ALG_SHA256;
    input.inPublic.publicArea.parameters.eccDetail.curveID = TPM_ECC_NIST_P256;
    input.inPublic.publicArea.parameters.eccDetail.kdf.scheme = TPM_ALG_NULL;
    input.inPublic.publicArea.parameters.eccDetail.kdf.details.mgf1.hashAlg = TPM_ALG_SHA256;

    input.inPublic.publicArea.authPolicy.b.size = AK_POLICY.size();
    static_cast<void>(std::move(AK_POLICY.cbegin(),
                                AK_POLICY.cend(),
                                input.inPublic.publicArea.authPolicy.b.buffer));

    Create_Out output{};
    const auto commandResult = TSS_Execute(mSession->getNative(),
                                           reinterpret_cast<RESPONSE_PARAMETERS*>(&output),
                                           reinterpret_cast<COMMAND_PARAMETERS*>(&input),
                                           nullptr,
                                           TPM_CC_Create,
                                           TPM_RS_PW,
                                           nullptr,
                                           0,
                                           TPM_RH_NULL,
                                           nullptr,
                                           0);

    if (commandResult)
    {
        throw Exception{"Unable to create attestation key: " + Utils::BuildErrorMessage(commandResult), commandResult};
    }

    return serializeTpmtKeyPair(TpmtKeyPair{std::move(output.outPrivate), std::move(output.outPublic)});
}

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

tpmclient::PublicKeyInfo tpmclient::Client::getAk(const KeyPairBlob& akBlob) const
{
    ClientUser clientUser{*this};

    loadAk(akBlob);

    return retrievePublicKey(mAkHandle);
}

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

tpmclient::MadeCredential tpmclient::Client::makeCredential(const KeyPairBlob& akBlob) const
{
    ClientUser clientUser{*this};

    loadAk(akBlob);

    const auto ak = retrievePublicKey(mAkHandle);

    createEk(false);

    MakeCredential_In input{};
    input.handle = mEkHandle;

    input.objectName.b.size = ak.name.size();
    static_cast<void>(std::move(ak.name.cbegin(), ak.name.cend(), input.objectName.b.buffer));

    const auto credential = getRandom(CREDENTIAL_SIZE);
    input.credential.b.size = credential.size();
    static_cast<void>(std::move(credential.cbegin(), credential.cend(), input.credential.b.buffer));

    MakeCredential_Out output{};
    const auto commandResult = TSS_Execute(mSession->getNative(),
                                           reinterpret_cast<RESPONSE_PARAMETERS*>(&output),
                                           reinterpret_cast<COMMAND_PARAMETERS*>(&input),
                                           nullptr,
                                           TPM_CC_MakeCredential,
                                           TPM_RH_NULL,
                                           nullptr,
                                           0);

    if (commandResult)
    {
        throw Exception{"Unable to make credential: " + Utils::BuildErrorMessage(commandResult),
                        commandResult};
    }

    Buffer secret(output.secret.b.size);
    static_cast<void>(std::move(output.secret.b.buffer,
                                output.secret.b.buffer + secret.size(),
                                secret.begin()));

    Buffer encryptedCredential(output.credentialBlob.b.size);
    static_cast<void>(std::move(output.credentialBlob.b.buffer,
                                output.credentialBlob.b.buffer + encryptedCredential.size(),
                                encryptedCredential.begin()));

    return MadeCredential{std::move(secret), std::move(credential), std::move(encryptedCredential)};
}

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

tpmclient::Buffer tpmclient::Client::authenticateCredential(const BufferView& secret,
                                                            const BufferView& encryptedCredential,
                                                            const KeyPairBlob& akBlob) const
{
    ClientUser clientUser{*this};

    loadAk(akBlob);

    createEk(false);

    ActivateCredential_In activateCredentialIn{};
    activateCredentialIn.activateHandle = mAkHandle;
    activateCredentialIn.keyHandle = mEkHandle;

    activateCredentialIn.credentialBlob.b.size = encryptedCredential.size();
    static_cast<void>(std::move(encryptedCredential.begin(),
                                encryptedCredential.end(),
                                activateCredentialIn.credentialBlob.b.buffer));

    activateCredentialIn.secret.b.size = secret.size();
    static_cast<void>(std::move(secret.begin(),
                                secret.end(),
                                activateCredentialIn.secret.b.buffer));

    PolicyCommandCode_In policyCommandCodeIn{};
    policyCommandCodeIn.policySession = startAuthSession();
    policyCommandCodeIn.code = 0x00000147;

    const auto policyCommandCodeCommandResult = TSS_Execute(mSession->getNative(),
                                                            nullptr,
                                                            reinterpret_cast<COMMAND_PARAMETERS*>(&policyCommandCodeIn),
                                                            nullptr,
                                                            TPM_CC_PolicyCommandCode,
                                                            TPM_RH_NULL,
                                                            nullptr,
                                                            0);

    if (policyCommandCodeCommandResult)
    {
        throw Exception{"Unable to authenticate credential: policy command code creation failed: " +
                        Utils::BuildErrorMessage(policyCommandCodeCommandResult),
                        policyCommandCodeCommandResult};
    }

    PolicySecret_In policySecretIn{};
    policySecretIn.policySession = startAuthSession();
    policySecretIn.authHandle = 0x4000000b;

    PolicySecret_Out policySecretOut{};
    const auto policySecretCommandResult = TSS_Execute(mSession->getNative(),
                                                       reinterpret_cast<RESPONSE_PARAMETERS*>(&policySecretOut),
                                                       reinterpret_cast<COMMAND_PARAMETERS*>(&policySecretIn),
                                                       nullptr,
                                                       TPM_CC_PolicySecret,
                                                       TPM_RS_PW,
                                                       nullptr,
                                                       0,
                                                       TPM_RH_NULL,
                                                       nullptr,
                                                       0);

    if (policySecretCommandResult)
    {
        throw Exception{"Unable to authenticate credential: policy secret creation failed: " +
                                                                    Utils::BuildErrorMessage(policySecretCommandResult),
                        policySecretCommandResult};
    }

    ActivateCredential_Out activateCredentialOut{};
    const auto activateCredentialCommandResult = TSS_Execute(
                                                          mSession->getNative(),
                                                          reinterpret_cast<RESPONSE_PARAMETERS*>(&activateCredentialOut),
                                                          reinterpret_cast<COMMAND_PARAMETERS*>(&activateCredentialIn),
                                                          nullptr,
                                                          TPM_CC_ActivateCredential,
                                                          policyCommandCodeIn.policySession,
                                                          nullptr,
                                                          0,
                                                          policySecretIn.policySession,
                                                          nullptr,
                                                          0,
                                                          TPM_RH_NULL,
                                                          nullptr,
                                                          0,
                                                          TPM_RH_NULL,
                                                          NULL,
                                                          0);

    if (activateCredentialCommandResult)
    {
        throw Exception{"Unable to authenticate credential: " +
                                                              Utils::BuildErrorMessage(activateCredentialCommandResult),
                        activateCredentialCommandResult};
    }

    Buffer result(activateCredentialOut.certInfo.t.size);
    static_cast<void>(std::move(activateCredentialOut.certInfo.t.buffer,
                                activateCredentialOut.certInfo.t.buffer + activateCredentialOut.certInfo.t.size,
                                result.begin()));

    return result;
}

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

tpmclient::Quote tpmclient::Client::getQuote(const BufferView& nonce,
                                             const PCRRegisterList& registerList,
                                             const KeyPairBlob& akBlob) const
{
    ClientUser clientUser{*this};

    loadAk(akBlob);

    Quote_In input{};
    input.signHandle = mAkHandle;
    input.inScheme.scheme = TPM_ALG_ECDSA;
    input.inScheme.details.ecdsa.hashAlg = TPM_ALG_SHA256;
    input.PCRselect.count = 1;
    input.PCRselect.pcrSelections->hash = TPM_ALG_SHA256;
    input.PCRselect.pcrSelections->sizeofSelect = 3;

    for (const auto registerValue : registerList)
    {
        if (registerValue > MAX_VALUE_PCR_REGISTER)
        {
            throw Exception{"Unable to get quote: unknown PCR register `" +
                            std::to_string(registerValue) +
                            "`. The maximum value is `" +
                            std::to_string(MAX_VALUE_PCR_REGISTER) +
                            "`."};
        }

        const auto pcrRegisterValue = static_cast<TPMI_DH_PCR>(registerValue);
        input.PCRselect.pcrSelections->pcrSelect[pcrRegisterValue / 8] |= 1 << (pcrRegisterValue % 8);
    }

    input.qualifyingData.b.size = nonce.size();
    static_cast<void>(std::move(nonce.cbegin(), nonce.cend(), input.qualifyingData.b.buffer));

    Quote_Out output{};
    const auto commandResult = TSS_Execute(mSession->getNative(),
                                           reinterpret_cast<RESPONSE_PARAMETERS*>(&output),
                                           reinterpret_cast<COMMAND_PARAMETERS*>(&input),
                                           nullptr,
                                           TPM_CC_Quote,
                                           TPM_RS_PW,
                                           nullptr,
                                           0,
                                           TPM_RH_NULL,
                                           nullptr,
                                           0);

    if (commandResult)
    {
        throw Exception{"Unable to get quote: " + Utils::BuildErrorMessage(commandResult), commandResult};
    }

    const auto* dummyBuffer = output.quoted.t.attestationData + sizeof(TPMS_ATTEST::magic) + sizeof(TPMS_ATTEST::type);
    std::uint16_t dummySize{};
    std::memcpy(&dummySize, dummyBuffer, sizeof(dummySize));
    dummySize = ntohs(dummySize);

    const auto* nonceResultBuffer = dummyBuffer + sizeof(dummySize) + dummySize;
    std::uint16_t nonceResultSize{};
    std::memcpy(&nonceResultSize, nonceResultBuffer, sizeof(nonceResultSize));
    nonceResultSize = ntohs(nonceResultSize);

    Buffer nonceResult(nonceResultSize);
    static_cast<void>(std::move(nonceResultBuffer + sizeof(nonceResultSize),
                                nonceResultBuffer + sizeof(nonceResultSize) + nonceResult.size(),
                                nonceResult.begin()));

    if (nonce != GetBufferView(nonceResult))
    {
        throw Exception{"Unable to get quote: resulting nonce does not match with the one used"};
    }

    Buffer quote(output.quoted.b.size);
    static_cast<void>(std::move(output.quoted.b.buffer,
                                output.quoted.b.buffer + output.quoted.b.size,
                                quote.begin()));

    return Quote{std::move(quote), serializeTssObject(output.signature, TSS_TPMT_SIGNATURE_Marshalu)};
}

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

void tpmclient::Client::verifyQuote(const Quote& quote, const KeyPairBlob& akBlob) const
{
    ClientUser clientUser{*this};

    loadAk(akBlob);

    VerifySignature_In input{};
    input.keyHandle = mAkHandle;

    deserializeTssObject(input.signature,
                         GetBufferView(quote.signature),
                         getGenericDeserializationFunction(TSS_TPMT_SIGNATURE_Unmarshalu));

    const auto quoteDigest = computeSha256(GetBufferView(quote.data));
    std::memcpy(input.digest.t.buffer, quoteDigest.data(), quoteDigest.size());
    input.digest.t.size = quoteDigest.size();

    VerifySignature_Out output{};
    const auto commandResult = TSS_Execute(mSession->getNative(),
                                           reinterpret_cast<RESPONSE_PARAMETERS*>(&output),
                                           reinterpret_cast<COMMAND_PARAMETERS*>(&input),
                                           nullptr,
                                           TPM_CC_VerifySignature,
                                           TPM_RH_NULL,
                                           nullptr,
                                           0);

    if (commandResult)
    {
        throw Exception{"Unable to verify quote: " + Utils::BuildErrorMessage(commandResult), commandResult};
    }
}

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

void tpmclient::Client::ensureIsValid() const
{
    if (!isValid())
    {
        throw Exception{"Unable to use client: it is invalid"};
    }
}

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

void tpmclient::Client::attemptToUse() const
{
    ensureIsValid();

    try
    {
        ping();
    }
    catch (const std::exception& ex)
    {
        throw Exception{"Unable to use client: " + std::string{ex.what()}};
    }
}

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

void tpmclient::Client::initialize() const
{
    ensureIsValid();

    Startup_In input{};
    input.startupType = TPM_SU_CLEAR;

    const auto commandResult = TSS_Execute(mSession->getNative(),
                                           nullptr,
                                           reinterpret_cast<COMMAND_PARAMETERS*>(&input),
                                           nullptr,
                                           TPM_CC_Startup,
                                           TPM_RH_NULL,
                                           nullptr,
                                           0);

    if (commandResult)
    {
        throw Exception{"Unable to initialize client: " + Utils::BuildErrorMessage(commandResult), commandResult};
    }
}

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

void tpmclient::Client::updateMaximumTransmissionUnit() const
{
    GetCapability_In input{};
    input.capability = TPM_CAP_TPM_PROPERTIES;
    input.property = TPM_PT_NV_BUFFER_MAX;
    input.propertyCount = 1;

    GetCapability_Out output{};
    const auto commandResult = TSS_Execute(mSession->getNative(),
                                           reinterpret_cast<RESPONSE_PARAMETERS*>(&output),
                                           reinterpret_cast<COMMAND_PARAMETERS*>(&input),
                                           nullptr,
                                           TPM_CC_GetCapability,
                                           TPM_RH_NULL,
                                           nullptr,
                                           0);
    if (commandResult)
    {
        throw Exception{"Unable to update MTU: " + Utils::BuildErrorMessage(commandResult), commandResult};
    }

    std::size_t dataMtu{};
    if (output.capabilityData.data.tpmProperties.count > 0 &&
        output.capabilityData.data.tpmProperties.tpmProperty->property == TPM_PT_NV_BUFFER_MAX)
    {
        dataMtu = output.capabilityData.data.tpmProperties.tpmProperty->value;
    }
    else
    {
        dataMtu = DEFAULT_DATA_MTU;
    }

    mDataMtu = std::make_unique<std::size_t>(std::min(dataMtu, static_cast<std::size_t>(MAX_NV_BUFFER_SIZE)));
}

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

std::size_t tpmclient::Client::queryDataSize(const StorageIndex& index) const
{
    NV_ReadPublic_In input{};
    input.nvIndex = index.getNative();

    NV_ReadPublic_Out output{};
    const auto commandResult = TSS_Execute(mSession->getNative(),
                                           reinterpret_cast<RESPONSE_PARAMETERS*>(&output),
                                           reinterpret_cast<COMMAND_PARAMETERS*>(&input),
                                           nullptr,
                                           TPM_CC_NV_ReadPublic,
                                           TPM_RH_NULL,
                                           nullptr,
                                           0);
    if (commandResult)
    {
        throw Exception{"Unable to query data size: " + Utils::BuildErrorMessage(commandResult), commandResult};
    }

    return output.nvPublic.nvPublic.dataSize;
}

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

tpmclient::Buffer tpmclient::Client::retrieveData(const StorageIndex& index) const
{
    if (!mDataMtu)
    {
        updateMaximumTransmissionUnit();
    }

    Buffer result(queryDataSize(index));
    auto writeItr = result.begin();

    NV_Read_In input{};
    input.authHandle = index.getNative();
    input.nvIndex = index.getNative();

    NV_Read_Out output{};
    while (writeItr != result.cend())
    {
        input.size = std::min(*mDataMtu, static_cast<std::size_t>(std::distance(writeItr, result.end())));

        const auto commandResult = TSS_Execute(mSession->getNative(),
                                               reinterpret_cast<RESPONSE_PARAMETERS*>(&output),
                                               reinterpret_cast<COMMAND_PARAMETERS*>(&input),
                                               nullptr,
                                               TPM_CC_NV_Read,
                                               TPM_RS_PW,
                                               nullptr,
                                               0,
                                               TPM_RH_NULL,
                                               nullptr,
                                               0);

        if (commandResult)
        {
            throw Exception{"Unable to read data from TPM: " + Utils::BuildErrorMessage(commandResult), commandResult};
        }

        writeItr = std::move(output.data.b.buffer, output.data.b.buffer + output.data.b.size, writeItr);
    }

    return result;
}

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

void tpmclient::Client::createPk() const
{
    CreatePrimary_In input{};
    input.primaryHandle = TPM_RH_ENDORSEMENT;

    input.inPublic.publicArea.type = TPM_ALG_ECC;
    input.inPublic.publicArea.nameAlg = TPM_ALG_SHA256;

    input.inPublic.publicArea.objectAttributes.val |= TPMA_OBJECT_NODA;
    input.inPublic.publicArea.objectAttributes.val |= TPMA_OBJECT_FIXEDTPM;
    input.inPublic.publicArea.objectAttributes.val |= TPMA_OBJECT_FIXEDPARENT;
    input.inPublic.publicArea.objectAttributes.val |= TPMA_OBJECT_SENSITIVEDATAORIGIN;
    input.inPublic.publicArea.objectAttributes.val |= TPMA_OBJECT_USERWITHAUTH;
    input.inPublic.publicArea.objectAttributes.val &= ~TPMA_OBJECT_ADMINWITHPOLICY;
    input.inPublic.publicArea.objectAttributes.val &= ~TPMA_OBJECT_SIGN;
    input.inPublic.publicArea.objectAttributes.val |= TPMA_OBJECT_DECRYPT;
    input.inPublic.publicArea.objectAttributes.val |= TPMA_OBJECT_RESTRICTED;

    input.inPublic.publicArea.parameters.eccDetail.symmetric.algorithm = TPM_ALG_AES;
    input.inPublic.publicArea.parameters.eccDetail.symmetric.keyBits.aes = 128;
    input.inPublic.publicArea.parameters.eccDetail.symmetric.mode.aes = TPM_ALG_CFB;
    input.inPublic.publicArea.parameters.eccDetail.scheme.scheme = TPM_ALG_NULL;
    input.inPublic.publicArea.parameters.eccDetail.curveID = TPM_ECC_NIST_P256;
    input.inPublic.publicArea.parameters.eccDetail.kdf.scheme = TPM_ALG_NULL;

    input.inPublic.publicArea.authPolicy.b.size = PK_POLICY.size();
    static_cast<void>(std::move(PK_POLICY.cbegin(),
                                PK_POLICY.cend(),
                                input.inPublic.publicArea.authPolicy.b.buffer));

    CreatePrimary_Out output{};
    const auto commandResult = TSS_Execute(mSession->getNative(),
                                           reinterpret_cast<RESPONSE_PARAMETERS*>(&output),
                                           reinterpret_cast<COMMAND_PARAMETERS*>(&input),
                                           nullptr,
                                           TPM_CC_CreatePrimary,
                                           TPM_RS_PW,
                                           nullptr,
                                           0,
                                           TPM_RH_NULL,
                                           nullptr,
                                           0);

    if (commandResult)
    {
        throw Exception{"Unable to create primary key: " + Utils::BuildErrorMessage(commandResult), commandResult};
    }

    mPkHandle = output.objectHandle;
}

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

void tpmclient::Client::loadAk(const KeyPairBlob& akBlob) const
{
    createPk();

    auto akKeyPair = deserializeTpmtKeyPair(GetBufferView(akBlob));

    Load_In input{};
    input.parentHandle = mPkHandle;
    input.inPrivate = std::move(akKeyPair.privatePart);
    input.inPublic = std::move(*akKeyPair.publicPart);

    Load_Out output{};
    const auto commandResult = TSS_Execute(mSession->getNative(),
                                           reinterpret_cast<RESPONSE_PARAMETERS*>(&output),
                                           reinterpret_cast<COMMAND_PARAMETERS*>(&input),
                                           nullptr,
                                           TPM_CC_Load,
                                           TPM_RS_PW,
                                           nullptr,
                                           0,
                                           TPM_RH_NULL,
                                           nullptr,
                                           0);

    if (commandResult)
    {
        throw Exception{"Unable to load key: " + Utils::BuildErrorMessage(commandResult), commandResult};
    }

    mAkHandle = output.objectHandle;
}

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

void tpmclient::Client::createEk(bool withCertificate) const
{
    CreatePrimary_In input{};
    input.primaryHandle = TPM_RH_ENDORSEMENT;

    const auto& storageIndexMap = StorageIndexMap::GetInstance();
    Utils::TryCatchFixRetry([this, &input, &storageIndexMap]()
                            {
                                if (!input.inPublic.publicArea.nameAlg)
                                {
                                    ScratchPad_setupEkInput(input.inPublic.publicArea,
                                                            retrieveData(storageIndexMap.getIndex(
                                                                         StorageIndexKey::PredefinedKeys::EK_TEMPLATE)),
                                                            retrieveData(storageIndexMap.getIndex(
                                                                           StorageIndexKey::PredefinedKeys::EK_NONCE)));
                                }
                            },
                            [](const auto& ex)
                            {
                                return (ex.getErrorCode() & 0xff) == TPM_RC_HANDLE;
                            },
                            [&input]()
                            {
                                ScratchPad_setupDefaultEkInput(input.inPublic.publicArea);
                            });

    CreatePrimary_Out output{};
    const auto commandResult = TSS_Execute(mSession->getNative(),
                                           reinterpret_cast<RESPONSE_PARAMETERS*>(&output),
                                           reinterpret_cast<COMMAND_PARAMETERS*>(&input),
                                           nullptr,
                                           TPM_CC_CreatePrimary,
                                           TPM_RS_PW,
                                           nullptr,
                                           0,
                                           TPM_RH_NULL,
                                           nullptr,
                                           0);

    if (commandResult)
    {
        throw Exception{"Unable to create EK: " + Utils::BuildErrorMessage(commandResult), commandResult};
    }

    mEkHandle = output.objectHandle;

    if (withCertificate)
    {
        const auto certificateToBeStored = ScratchPad_getFinalEKCert(&output.outPublic.publicArea);
        const auto ekCertificateStorageIndex = storageIndexMap.getIndex(StorageIndexKey::PredefinedKeys::EK_CERTIFICATE);

        if (0 != ScratchPad_defineEKCertIndex(mSession->getNative(),
                                              certificateToBeStored.first.size(),
                                              ekCertificateStorageIndex.getNative(),
                                              nullptr))
        {
            throw Exception("ScratchPad_defineEKCertIndex failure");
        }

        if (0 != ScratchPad_storeEkCertificate(mSession->getNative(),
                                               *mDataMtu,
                                               certificateToBeStored.first.size(),
                                               certificateToBeStored.first.data(),
                                               ekCertificateStorageIndex.getNative(),
                                               nullptr))
        {
            throw Exception("ScratchPad_storeEkCertificate failure");
        }
    }
}

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

void tpmclient::Client::flushKeys() const
{
    if (IsSoftwareTpm())
    {
        FlushContext_In input{};
        const auto flushKey = [&input, this](auto keyHandle)
        {
            input.flushHandle = keyHandle;
            const auto commandResult = TSS_Execute(mSession->getNative(),
                                                   nullptr,
                                                   reinterpret_cast<COMMAND_PARAMETERS*>(&input),
                                                   nullptr,
                                                   TPM_CC_FlushContext,
                                                   TPM_RH_NULL,
                                                   nullptr,
                                                   0);

            if (commandResult && (commandResult & (0x03f | RC_FMT1)) != TPM_RC_HANDLE)
            {
                throw Exception{"Unable to flush key: " + Utils::BuildErrorMessage(commandResult), commandResult};
            }
        };

        for (const auto handle : {mPkHandle, mAkHandle, mEkHandle})
        {
            if (handle)
            {
                flushKey(handle);
            }
        }
    }
}

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

int tpmclient::Client::startAuthSession() const
{
    StartAuthSession_In input{};
    input.sessionType = TPM_SE_POLICY;
    input.tpmKey = TPM_RH_NULL;
    input.bind = TPM_RH_NULL;
    input.authHash = TPM_ALG_SHA256;
    input.symmetric.algorithm = TPM_ALG_XOR;
    input.symmetric.mode.sym = TPM_ALG_NULL;
    input.symmetric.keyBits.xorr = TPM_ALG_SHA256;

    StartAuthSession_Out output{};
    const auto commandResult = TSS_Execute(mSession->getNative(),
                                           reinterpret_cast<RESPONSE_PARAMETERS*>(&output),
                                           reinterpret_cast<COMMAND_PARAMETERS*>(&input),
                                           nullptr,
                                           TPM_CC_StartAuthSession,
                                           TPM_RH_NULL,
                                           nullptr,
                                           0);

    if (commandResult)
    {
        throw Exception{"Unable to start authentication session: " + Utils::BuildErrorMessage(commandResult),
                        commandResult};
    }

    return output.sessionHandle;
}

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

tpmclient::Buffer tpmclient::Client::getRandom(std::size_t bytes) const
{
    GetRandom_In input{};
    input.bytesRequested = bytes;

    GetRandom_Out output{};
    const auto commandResult = TSS_Execute(mSession->getNative(),
                                           reinterpret_cast<RESPONSE_PARAMETERS*>(&output),
                                           reinterpret_cast<COMMAND_PARAMETERS*>(&input),
                                           nullptr,
                                           TPM_CC_GetRandom,
                                           TPM_RH_NULL,
                                           nullptr,
                                           0);

    if (commandResult)
    {
        throw Exception{"Unable to get random: " + Utils::BuildErrorMessage(commandResult), commandResult};
    }

    Buffer result(output.randomBytes.t.size);
    static_cast<void>(std::move(output.randomBytes.t.buffer,
                                output.randomBytes.t.buffer + output.randomBytes.t.size,
                                result.begin()));

    return result;
}

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

tpmclient::PublicKeyInfo tpmclient::Client::retrievePublicKey(std::uint32_t handle) const
{
    if (!handle)
    {
        throw Exception{"Unable to retrieve public key: logic error: invalid handle provided"};
    }

    ReadPublic_In input{};
    input.objectHandle = handle;

    ReadPublic_Out output{};
    const auto commandResult = TSS_Execute(mSession->getNative(),
                                           reinterpret_cast<RESPONSE_PARAMETERS*>(&output),
                                           reinterpret_cast<COMMAND_PARAMETERS*>(&input),
                                           nullptr,
                                           TPM_CC_ReadPublic,
                                           TPM_RH_NULL,
                                           nullptr,
                                           0);

    if (commandResult)
    {
        throw Exception{"Unable to retrieve public key: " + Utils::BuildErrorMessage(commandResult),
                        commandResult};
    }

    PublicKeyName publicKeyName{};
    static_cast<void>(std::move(output.name.t.name, output.name.t.name + output.name.t.size, publicKeyName.begin()));

    return PublicKeyInfo{serializeTssObject(output.outPublic, TSS_TPM2B_PUBLIC_Marshalu), std::move(publicKeyName)};
}

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
