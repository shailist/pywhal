cmake_minimum_required(VERSION 3.15...3.26)
project(${SKBUILD_PROJECT_NAME} LANGUAGES CXX)

set(PYBIND11_FINDPYTHON ON)
find_package(pybind11 CONFIG REQUIRED)

add_subdirectory(deps/Detours)

pybind11_add_module(_core MODULE src/main.cpp)
target_link_libraries(_core PRIVATE libdetours)
set_property(TARGET _core PROPERTY CXX_STANDARD 20)

install(TARGETS _core DESTINATION ${SKBUILD_PROJECT_NAME})
