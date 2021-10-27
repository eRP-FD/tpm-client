/*
 * (C) Copyright IBM Deutschland GmbH 2021
 * (C) Copyright IBM Corp. 2021
 * SPDX-License-Identifier: CC BY-NC-ND 3.0 DE
 */

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

#ifndef TPM_CLIENT_UTILS_H
#define TPM_CLIENT_UTILS_H

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

#include "Exception.h"

#include <cstdint>
#include <functional>
#include <iterator>
#include <string>
#include <type_traits>

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

namespace tpmclient
{

/**
 * Static class containing utility functions used throughout tpmclient.
 */
class Utils
{
public:
    /**
     * Builds an error message string describing what the given error code means.
     * Used exclusively with TSS (underlying library) error codes.
     */
    static std::string BuildErrorMessage(Exception::NativeErrorCodeType errorCode);

    /**
     * Attempts the try operation. If it does not fail, it returns its result.
     *
     * If it fails and the failing condition matches `catchCondition`,
     * then it calls `fixOperation` and retries the initial operation.
     *
     * If the failing condition does not match or if the `fixOperation` fails too or
     * if the initial operation fails again after fixing, the error is rethrown to the caller.
     */
    template <typename TryOperation, typename CatchCondition, typename FixOperation>
    static std::invoke_result_t<TryOperation> TryCatchFixRetry(const TryOperation& tryOperation,
                                                               const CatchCondition& catchCondition,
                                                               const FixOperation& fixOperation);

    /**
     * Concatenates given buffers by moving from them.
     */
    template <typename HeadT, typename ...TailT>
    static HeadT ConcatenateBuffers(HeadT&& head, TailT&&... tail);

    /**
     * Retrieves the n'th byte of the given 64-bit unsigned integer.
     */
    static std::uint8_t GetNthByte(std::uint64_t input, std::size_t index);
};

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

template <typename TryOperation, typename CatchCondition, typename FixOperation>
std::invoke_result_t<TryOperation> Utils::TryCatchFixRetry(const TryOperation& tryOperation,
                                                           const CatchCondition& catchCondition,
                                                           const FixOperation& fixOperation)
{
    try
    {
        return tryOperation();
    }
    catch (const Exception& ex)
    {
        if (!catchCondition(ex))
        {
            throw;
        }

        fixOperation();
        return tryOperation();
    }
}

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

template <typename HeadT, typename ...TailT>
HeadT Utils::ConcatenateBuffers(HeadT&& head, TailT&&... tail)
{
    static_assert(std::is_rvalue_reference_v<HeadT&&>);
    static_assert((std::is_rvalue_reference_v<TailT&&> && ...));

    HeadT concatenationResult{};
    concatenationResult.reserve(head.size() + (tail.size() + ...));

    concatenationResult.insert(concatenationResult.end(),
                               std::make_move_iterator(head.begin()),
                               std::make_move_iterator(head.end())),

    (
            concatenationResult.insert(concatenationResult.end(),
                                       std::make_move_iterator(tail.begin()),
                                       std::make_move_iterator(tail.end())),
            ...
    );

    return concatenationResult;
}

}

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

#endif

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
