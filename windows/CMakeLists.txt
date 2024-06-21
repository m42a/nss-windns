cmake_minimum_required(VERSION 3.28)

set(CMAKE_CXX_STANDARD 23)

project(windns_proxy VERSION 1.0 LANGUAGES CXX)

add_executable(windns_proxy WIN32 windns_proxy.cpp)
