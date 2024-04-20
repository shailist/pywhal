#include <bit>
#include <list>
#include <pybind11/pybind11.h>
#include <Windows.h>
#include <detours.h>

#include "pywhal/bindings/hooks.hpp"

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
}
