# Based on https://github.com/hasherezade/detours_cmake_tpl

cmake_minimum_required(VERSION 3.0)
project(libdetours VERSION 4.0.1)

set(CMAKE_CXX_FLAGS_RELEASE "${CMAKE_CXX_FLAGS_RELEASE} /MT /W4 /WX /Zi /MT /Gy /Gm- /Zl /Od")

option(DETOURS_CL_17_OR_NEWER "DETOURS_CL_17_OR_NEWER" ON)
option(DETOURS_WIN_7 "DETOURS_WIN_7" OFF)
option(DETOURS_SOURCE_BROWSING "DETOURS_SOURCE_BROWSING" ON)

if((NOT ${DETOURS_WIN_7}) AND ${DETOURS_CL_17_OR_NEWER})
    set(CMAKE_CXX_FLAGS_RELEASE "${CMAKE_CXX_FLAGS_RELEASE} /D_USING_V110_SDK71_")
endif()

if(DETOURS_SOURCE_BROWSING)
    set(CMAKE_CXX_FLAGS_RELEASE "${CMAKE_CXX_FLAGS_RELEASE} /FR")
else()
    set(CMAKE_CXX_FLAGS_RELEASE "${CMAKE_CXX_FLAGS_RELEASE} /DWIN32_LEAN_AND_MEAN /D_WIN32_WINNT=0x501")
endif()

if(CMAKE_SIZEOF_VOID_P EQUAL 8)
    add_definitions(-D_AMD64_)
else()
    add_definitions(-D_X86_)
endif()

add_library(${PROJECT_NAME} STATIC)

target_sources(${PROJECT_NAME}
    PRIVATE
        Detours/src/creatwth.cpp
        Detours/src/detours.cpp
        Detours/src/disasm.cpp
        Detours/src/disolarm.cpp
        Detours/src/disolarm64.cpp
        Detours/src/disolia64.cpp
        Detours/src/disolx64.cpp
        Detours/src/disolx86.cpp
        Detours/src/image.cpp
        Detours/src/modules.cpp
)

target_include_directories(${PROJECT_NAME} PUBLIC Detours/src)
