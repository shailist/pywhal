#pragma once

#include "../detours.hpp"
#include <pybind11/pybind11.h>

namespace pywhal::bindings::hooks
{
	uintptr_t attach_hook(uintptr_t original_function, uintptr_t detour_function);
	uintptr_t detach_hook(uintptr_t trampoline_function, uintptr_t detour_function);

    void register_submodule(pybind11::module_& m);
}

////////////////////
// Implementation //
////////////////////

namespace pywhal::bindings::hooks
{
    inline uintptr_t attach_hook(const uintptr_t original_function, const uintptr_t detour_function)
    {
        auto* trampoline_function = std::bit_cast<void*>(original_function);

        detours::transaction(
            [&](detours::Transaction& transaction) {
                transaction.attach(trampoline_function, std::bit_cast<void*>(detour_function));
            }
        );

        return std::bit_cast<uintptr_t>(trampoline_function);
    }

    inline uintptr_t detach_hook(const uintptr_t trampoline_function, const uintptr_t detour_function)
    {
        auto* original_function = std::bit_cast<void*>(trampoline_function);

    	detours::transaction(
            [&](detours::Transaction& transaction) {
                transaction.detach(original_function, std::bit_cast<void*>(detour_function));
            }
        );

        return std::bit_cast<uintptr_t>(original_function);
    }

    inline void register_submodule(pybind11::module_& m)
    {
        auto hooks_module = m.def_submodule("hooks", R"pbdoc(
	        Module that implements native function detouring.
	    )pbdoc");

    	hooks_module.def("attach_hook", &attach_hook, R"pbdoc(
	        Attaches a detour to a function.
	        Returns a trampoline function that can be used to call the original function.
	    )pbdoc");

    	hooks_module.def("detach_hook", &detach_hook, R"pbdoc(
	        Detaches a detour from a function.
	        Requires the trampoline function as a parameter.
	        Returns the address of the original function.
	    )pbdoc");
    }
}
