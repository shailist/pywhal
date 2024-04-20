#pragma once

#include "./type_traits.hpp"

namespace pywhal::detours
{
    namespace detail
    {
        struct TransactionHelper;
    }

    class Transaction
    {
    public:
        void attach(void*& function, void* detour_function);
        void detach(void*& function, void* detour_function);

        template <type_traits::function_pointer TFunction>
        void attach(TFunction& function, TFunction detour_function);

        template <type_traits::function_pointer TFunction>
        void detach(TFunction& function, TFunction detour_function);

    private:
        friend struct detail::TransactionHelper;

    private:
        Transaction() = default;
    };

    template <typename TCallable> requires std::is_invocable_v<TCallable, Transaction&>
    void transaction(TCallable&& callback);
}

////////////////////
// Implementation //
////////////////////

#include <Windows.h>
#include <detours.h>

namespace pywhal::detours
{
    namespace detail
    {
        struct TransactionHelper
        {
            static Transaction create_transaction()
            {
                return Transaction();
            }
        };
    }

    // ReSharper disable once CppMemberFunctionMayBeStatic
    inline void Transaction::attach(void*& function, void* detour_function)
    {
        const auto attach_result = DetourAttach(std::addressof(function), detour_function);
        if (NO_ERROR != attach_result)
        {
            throw std::system_error(attach_result, std::system_category(), "DetourAttach failed");
        }
    }

    // ReSharper disable once CppMemberFunctionMayBeStatic
    inline void Transaction::detach(void*& function, void* detour_function)
    {
        const auto detach_result = DetourDetach(std::addressof(function), detour_function);
        if (NO_ERROR != detach_result)
        {
            throw std::system_error(detach_result, std::system_category(), "DetourDetach failed");
        }
    }

    template<pywhal::type_traits::function_pointer TFunction>
    void Transaction::attach(TFunction& function, TFunction detour_function)
    {
        attach(reinterpret_cast<void*&>(function), std::bit_cast<void*>(detour_function));
    }

    template <pywhal::type_traits::function_pointer TFunction>
    void Transaction::detach(TFunction& function, TFunction detour_function)
    {
        detach(reinterpret_cast<void*&>(function), std::bit_cast<void*>(detour_function));
    }

    template <typename TCallable> requires std::is_invocable_v<TCallable, Transaction&>
    void transaction(TCallable&& callback)
    {
        const auto begin_result = DetourTransactionBegin();
        if (NO_ERROR != begin_result)
        {
            throw std::system_error(begin_result, std::system_category(), "DetourTransactionBegin failed");
        }

        try
        {
            auto transaction = detail::TransactionHelper::create_transaction();
            std::invoke(std::forward<TCallable>(callback), transaction);

            const auto commit_result = DetourTransactionCommit();
            if (NO_ERROR != commit_result)
            {
                throw std::system_error(commit_result, std::system_category(), "DetourTransactionCommit failed");
            }
        }
        catch (...)
        {
            DetourTransactionAbort();
            throw;
        }
    }
}
