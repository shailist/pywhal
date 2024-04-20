cmake_minimum_required(VERSION 3.15...3.26)
project(${SKBUILD_PROJECT_NAME} LANGUAGES CXX)

add_subdirectory(src/cpp)

install(TARGETS pywhalCore DESTINATION ${SKBUILD_PROJECT_NAME})
