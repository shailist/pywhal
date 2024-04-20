cmake_minimum_required(VERSION 3.15...3.26)
project(pywhalCore LANGUAGES CXX)

set(PYBIND11_FINDPYTHON ON)
find_package(pybind11 CONFIG REQUIRED)

pybind11_add_module(${PROJECT_NAME} MODULE)

set_target_properties(${PROJECT_NAME}
	PROPERTIES
		CXX_STANDARD 20
		OUTPUT_NAME _pywhalCore
)

add_subdirectory(deps/Detours)
target_link_libraries(${PROJECT_NAME} PRIVATE libdetours)

target_sources(${PROJECT_NAME}
	PRIVATE
		main.cpp
)

add_subdirectory(pywhal)
