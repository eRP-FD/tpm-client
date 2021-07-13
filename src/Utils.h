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
 * TODO TSB
 */
class Utils
{
public:
    /**
     * TODO TSB
     */
    static std::string BuildErrorMessage(Exception::NativeErrorCodeType errorCode);

    /**
     * TODO TSB
     */
    template <typename TryOperation, typename CatchCondition, typename FixOperation>
    static std::invoke_result_t<TryOperation> TryCatchFixRetry(const TryOperation& tryOperation,
                                                               const CatchCondition& catchCondition,
                                                               const FixOperation& fixOperation);

    /**
     * TODO TSB
     */
    template <typename HeadT, typename ...TailT>
    static HeadT ConcatenateBuffers(HeadT&& head, TailT&&... tail);

    /**
     * TODO TSB
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
