cmake_minimum_required(VERSION 3.29)

set(CMAKE_CXX_STANDARD 23)

project(windns_nss VERSION 1.0 LANGUAGES CXX)

include(GNUInstallDirs)

# The main library
add_library(nss_windns SHARED nss_windns.cpp)
target_compile_options(nss_windns PRIVATE
	-Wall
	-Wextra
	-Wno-missing-field-initializers
	# Avoid needing to link libstdc++
	-fno-exceptions
)
target_link_options(nss_windns PRIVATE
	# Avoid linking libstdc++ so it doesn't get unnecessarily loaded by C programs
	-nostdlib++

	# Make the linker fail when referencing functions that don't exist
	LINKER:-z,defs

	# Make the import table read-only (not necessary, but good security practice)
	LINKER:-z,relro
	LINKER:-z,now
)
set_target_properties(nss_windns PROPERTIES
	SOVERSION 2
)

# A library that can be preloaded to force any program to use libnss_windns without changing /etc/nsswitch.conf
add_library(force_windns SHARED force_windns.cpp)
target_compile_options(force_windns PRIVATE
	-fno-exceptions
)
target_link_options(force_windns PRIVATE
	-nostdlib++
)
add_dependencies(force_windns nss_windns)

# A program that calls in to every significant function in libnss_windns
add_executable(windns_test test.cpp)
add_dependencies(windns_test nss_windns)

install(TARGETS nss_windns
	LIBRARY
	NAMELINK_SKIP
	DESTINATION ${CMAKE_INSTALL_LIBDIR}
)
