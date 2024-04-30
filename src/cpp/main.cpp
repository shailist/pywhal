#include "pywhal/bindings/hooks.hpp"
#include "pywhal/bindings/memory.hpp"

namespace py = pybind11;

PYBIND11_MODULE(_pywhalCore, m)
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

    pywhal::bindings::hooks::register_submodule(m);
    pywhal::bindings::memory::register_submodule(m);
}
