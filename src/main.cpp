#include <bit>
#include <list>
#include <pybind11/pybind11.h>
#include <Windows.h>
#include <detours.h>

#include <type_traits>

namespace pywhal
{
	namespace type_traits
	{
        template <typename T>
        constexpr bool is_function_pointer_v = std::is_pointer_v<T> && std::is_function_v<std::remove_pointer_t<T>>;

        template <typename T>
        using is_function_pointer = std::bool_constant<is_function_pointer_v<T>>;

        template <typename T>
        concept function_pointer = is_function_pointer_v<T>;
	}
}

namespace Detours
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

        template <pywhal::type_traits::function_pointer TFunction>
        void attach(TFunction& function, TFunction detour_function);

        template <pywhal::type_traits::function_pointer TFunction>
        void detach(TFunction& function, TFunction detour_function);

    private:
        friend struct detail::TransactionHelper;

    private:
        Transaction() = default;
    };

    template <typename TCallable> requires std::is_invocable_v<TCallable, Transaction&>
    void transaction(TCallable&& callback);
}

namespace Detours
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

////////////////////
// Implementation //
////////////////////

uintptr_t attach_hook(uintptr_t original_function, uintptr_t detour_function);
uintptr_t detach_hook(uintptr_t trampoline_function, uintptr_t detour_function);

inline uintptr_t attach_hook(uintptr_t original_function, const uintptr_t detour_function)
{
    Detours::transaction(
        [&](Detours::Transaction& transaction) {
            transaction.attach(reinterpret_cast<void*&>(original_function), std::bit_cast<void*>(detour_function));
        }
    );

    return original_function;
}

inline uintptr_t detach_hook(uintptr_t trampoline_function, const uintptr_t detour_function)
{
    Detours::transaction(
        [&](Detours::Transaction& transaction) {
            transaction.detach(reinterpret_cast<void*&>(trampoline_function), std::bit_cast<void*>(detour_function));
        }
    );

    return std::bit_cast<uintptr_t>(trampoline_function);
}

namespace py = pybind11;

PYBIND11_MODULE(_core, m)
{
    m.doc() = R"pbdoc(
        pywhal - Python Windows HAcking Library
        -----------------------
        .. currentmodule:: pywhal
        .. autosummary::
            :toctree: _generate
            add
            subtract
    )pbdoc";

    m.def("attach_hook", &attach_hook, R"pbdoc(
        Attaches a detour to a function.
        Returns a trampoline function that can be used to call the original function.
    )pbdoc");

    m.def("detach_hook", &detach_hook, R"pbdoc(
        Detaches a detour from a function.
        Requires the trampoline function as a parameter.
        Returns the address of the original function.
    )pbdoc");
}
