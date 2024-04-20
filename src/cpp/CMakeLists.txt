cmake_minimum_required(VERSION 3.15...3.26)
project(pywhalCore LANGUAGES CXX)

find_package(pybind11 CONFIG REQUIRED)

add_library(${PROJECT_NAME} MODULE)

set_property(TARGET ${PROJECT_NAME} PROPERTY CXX_STANDARD 20)

target_link_libraries(${PROJECT_NAME} PUBLIC pybind11::module)

add_subdirectory(deps/Detours)
target_link_libraries(${PROJECT_NAME} PRIVATE libdetours)

target_sources(${PROJECT_NAME}
	PRIVATE
		main.cpp
)

