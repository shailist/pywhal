#include <pybind11/pybind11.h>
#include <Windows.h>

uintptr_t attach_hook(uintptr_t original_function, uintptr_t detour_function)
{
    return 0;
}

uintptr_t detach_hook(uintptr_t trampoline_function, uintptr_t detour_function)
{
    return 0;
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
