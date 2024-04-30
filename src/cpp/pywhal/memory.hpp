#pragma once

#include <bit>
#include <format>
#include <stdexcept>
#include <string>
#include <Windows.h>
#include <winternl.h>

namespace pywhal::memory
{
	[[nodiscard]] std::string read_process_memory(HANDLE process_handle, uint64_t address, uint64_t size);
}

////////////////////
// Implementation //
////////////////////

namespace pywhal::memory
{
    namespace detail
    {
    	using PfnNtReadVirtualMemory = NTSTATUS(NTAPI*)(
            _In_ HANDLE ProcessHandle,
            _In_opt_ PVOID BaseAddress,
            _Out_writes_bytes_(BufferSize) PVOID Buffer,
            _In_ SIZE_T BufferSize,
            _Out_opt_ PSIZE_T NumberOfBytesRead
        );

        [[nodiscard]] inline std::string read_virtual_memory(const HANDLE process_handle, const uint64_t address, const uint64_t size)
    	{
            static PfnNtReadVirtualMemory NtReadVirtualMemory = std::invoke(
                [] {
                    auto* pfnNtReadVirtualMemory = std::bit_cast<PfnNtReadVirtualMemory>(GetProcAddress(GetModuleHandleA("ntdll.dll"), "NtReadVirtualMemory"));
                    if (pfnNtReadVirtualMemory == nullptr)
                    {
                        throw std::runtime_error("Could not find NtReadVirtualMemory function");
                    }
                    return pfnNtReadVirtualMemory;
                }
            );

            std::string buffer;
            buffer.resize(static_cast<size_t>(size));

            const auto result = NtReadVirtualMemory(process_handle, reinterpret_cast<PVOID>(address), buffer.data(), buffer.size(), nullptr);
            if (!NT_SUCCESS(result))
            {
                throw std::runtime_error(std::format("NtReadVirtualMemory failed with status 0x{:08x}", static_cast<uint32_t>(result)));
            }

            return buffer;
    	}

#ifndef _WIN64

        using PfnNtWow64ReadVirtualMemory64 = NTSTATUS(NTAPI*)(
            _In_ HANDLE ProcessHandle,
            _In_opt_ PVOID64 BaseAddress,
            _Out_writes_bytes_(BufferSize) PVOID Buffer,
            _In_ ULONG64 BufferSize,
            _Out_opt_ PULONG64 NumberOfBytesRead
        );

        [[nodiscard]] inline std::string read_virtual_memory_64(const HANDLE process_handle, const uint64_t address, const uint64_t size)
        {
            static PfnNtWow64ReadVirtualMemory64 NtWow64ReadVirtualMemory64 = std::invoke(
                [] {
                    auto* pfnNtWow64ReadVirtualMemory64 = std::bit_cast<PfnNtWow64ReadVirtualMemory64>(GetProcAddress(GetModuleHandleA("ntdll.dll"), "NtWow64ReadVirtualMemory64"));
                    if (pfnNtWow64ReadVirtualMemory64 == nullptr)
                    {
                        throw std::runtime_error("Could not find NtWow64ReadVirtualMemory64 function");
                    }
                    return pfnNtWow64ReadVirtualMemory64;
                }
            );

            std::string buffer;
            buffer.resize(static_cast<size_t>(size));

            const auto result = NtWow64ReadVirtualMemory64(process_handle, reinterpret_cast<PVOID64>(address), buffer.data(), buffer.size(), nullptr);
            if (!NT_SUCCESS(result))
            {
                throw std::runtime_error(std::format("NtWow64ReadVirtualMemory64 failed with status 0x{:08x}", static_cast<uint32_t>(result)));
            }

            return buffer;
		}
#endif

    }

    inline std::string read_process_memory(const HANDLE process_handle, const uint64_t address, const uint64_t size)
    {

#ifndef _WIN64

        BOOL process_is_32bit;
        if (!IsWow64Process(process_handle, std::addressof(process_is_32bit)))
        {
            throw std::runtime_error("Could not determine if process is 32 or 64 bit");
        }

        if (!process_is_32bit)
        {
            return detail::read_virtual_memory_64(process_handle, address, size);
        }
#endif

        return detail::read_virtual_memory(process_handle, address, size);
    }
}
