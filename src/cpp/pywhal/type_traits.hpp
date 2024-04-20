#pragma once

#include <type_traits>

namespace pywhal::type_traits
{
    template <typename T>
    constexpr bool is_function_pointer_v = std::is_pointer_v<T> && std::is_function_v<std::remove_pointer_t<T>>;

    template <typename T>
    using is_function_pointer = std::bool_constant<is_function_pointer_v<T>>;

    template <typename T>
    concept function_pointer = is_function_pointer_v<T>;
}
