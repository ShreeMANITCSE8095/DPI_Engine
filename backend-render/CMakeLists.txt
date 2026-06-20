cmake_minimum_required(VERSION 3.14)
project(DPIEngine CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

if(NOT CMAKE_BUILD_TYPE)
  set(CMAKE_BUILD_TYPE Release)
endif()
set(CMAKE_CXX_FLAGS_RELEASE "-O2")

include_directories(include)

set(SHARED_SOURCES
    src/pcap_reader.cpp
    src/packet_parser.cpp
    src/sni_extractor.cpp
    src/types.cpp
    src/connection_tracker.cpp
    src/rule_manager.cpp
)

# Web JSON binary
add_executable(dpi_json
    ${SHARED_SOURCES}
    src/main_json.cpp
)

# Original CLI analyzer
add_executable(packet_analyzer
    ${SHARED_SOURCES}
    src/main.cpp
)
