cmake_minimum_required (VERSION 3.7)

# Project name
project (its_bridge C)

include(CheckCCompilerFlag)

# Project version
set(its_bridge VERSION_MAJOR 1)
set(its_bridge VERSION_MINOR 1)

# Install directories
include(GNUInstallDirs)

# Copy output file into lib directory
set(EXECUTABLE_OUTPUT_PATH "../bin")
set(CMAKE_RUNTIME_OUTPUT_DIRECTORY "../bin")
# Copy output file into bin directory
set(CMAKE_LIBRARY_OUTPUT_DIRECTORY "../lib")
set(CMAKE_ARCHIVE_OUTPUT_DIRECTORY "../lib")

# Setup library source files
set(its_bridge_client_SOURCES "../src/utils.c" "../src/its_bridge_client.c")
set(its_bridge_server_SOURCES "../src/utils.c" "../src/its_bridge_server.c")
set(its_web_server_config_SOURCES "../src/utils.c" "../src/its_web_server_config.c")

# Setup header files path
include_directories(
  "../include"
  "/usr/local/include"
  )

# Add libpcap support
link_directories(/usr/lib/x86_64-linux-gnu/libpcap.so /usr/lib/x86_64-linux-gnu)
link_directories(/usr/local/lib/libmicrohttpd.so /usr/local/lib)

# Testing application source files dependencies
add_executable(its_bridge_client ${its_bridge_client_SOURCES})
target_link_libraries(its_bridge_client pcap)
add_executable(its_bridge_server ${its_bridge_server_SOURCES})
target_link_libraries(its_bridge_server pcap)
add_executable(its_web_server_config ${its_web_server_config_SOURCES})
target_link_libraries(its_web_server_config microhttpd)

# Packaging
set(CMAKE_EXPORT_PACKAGE_REGISTRY ON)
configure_file(its_bridge_clientConfig.cmake.in its_bridge_clientConfig.cmake)
export(PACKAGE its_bridge_client)
configure_file(its_bridge_serverConfig.cmake.in its_bridge_serverConfig.cmake)
export(PACKAGE its_bridge_server)
configure_file(its_web_server_configConfig.cmake.in its_web_server_configConfig.cmake)
export(PACKAGE its_web_server_config)

# Installation
set_target_properties(its_bridge_client PROPERTIES PUBLIC_HEADER "../include/its_bridge_client.h;../include/utils.h")
set_target_properties(its_bridge_server PROPERTIES PUBLIC_HEADER "../include/its_bridge_server.h;../include/utils.h")
set_target_properties(its_web_server_config PROPERTIES PUBLIC_HEADER "../include/its_web_server_config.h;../include/utils.h")
install(
  TARGETS its_bridge_client its_bridge_server its_web_server_config
  RUNTIME DESTINATION $ENV{HOME_BIN}
  LIBRARY DESTINATION $ENV{HOME_LIB}
  ARCHIVE DESTINATION $ENV{HOME_LIB}
  PUBLIC_HEADER DESTINATION $ENV{HOME_INC}
  )

# Deinstallation
configure_file (
  "deinstall.cmake.in"
  "deinstall.cmake"
  IMMEDIATE @ONLY
  )
add_custom_target(deinstall
  COMMAND ${CMAKE_COMMAND} -P "deinstall.cmake"
  OUTPUT_VARIABLE rm_out
  RESULT_VARIABLE rm_retval
  )

# Custom targets
add_custom_target(distclean
  # cmake files production
  COMMAND make clean &&
    find . -name 'CMakeCache.txt' -type f -exec rm -f {} "\;" &&
    find . -name '*.cmake' -type f -exec rm -f {} "\;" &&
    find . -name 'install_manifest.txt' -type f -exec rm -f {} "\;" &&
    find . -name 'Makefile' -type f -exec rm -f {} "\;" &&
    find . -name 'CMakeDoxyfile.in' -type f -exec rm -f {} "\;" &&
    find . -name '*~' -type f -exec rm -f {} "\;" &&
    find . -name 'CMakeFiles' -type d -exec rm -fr {} "\;" &&
    find . -name 'html' -type d -exec rm -fr {} "\;" &&
    find . -name 'latex' -type d -exec rm -fr {} "\;" &&
    find . -name 'man' -type d -exec rm -fr {} "\;"
  )

