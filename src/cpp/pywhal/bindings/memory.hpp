#pragma once

#include "../memory.hpp"
#include <pybind11/pybind11.h>

namespace pywhal::bindings::memory
{
	pybind11::bytes read_process_memory(size_t handle, uint64_t address, uint64_t size);

    void register_submodule(pybind11::module_& m);
}

////////////////////
// Implementation //
////////////////////

namespace pywhal::bindings::memory
{
	inline pybind11::bytes read_process_memory(const size_t handle, const uint64_t address, const uint64_t size)
	{
		return pywhal::memory::read_process_memory(reinterpret_cast<HANDLE>(handle), address, size);
	}

    inline void register_submodule(pybind11::module_& m)
    {
        auto memory_module = m.def_submodule("memory", R"pbdoc(
	        Module that implements memory primitives.
	    )pbdoc");

		memory_module.def("read_process_memory", &read_process_memory, R"pbdoc(
	        Reads memory from a given process.
	        Assumes the given handle has PROCESS_VM_READ access rights.
	    )pbdoc");
    }
}
