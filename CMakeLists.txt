cmake_minimum_required(VERSION 3.20)

project(EasyTier LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

# Compiler-specific coroutine flags
if(CMAKE_CXX_COMPILER_ID STREQUAL "GNU")
    add_compile_options(-fcoroutines)
endif()

# ---- async_net library ----
set(ASYNC_NET_DIR "/work/study/async_net" CACHE PATH "Path to async_net library")

# Import async_net as a pre-built library
add_library(async_net STATIC IMPORTED)
set_target_properties(async_net PROPERTIES
        IMPORTED_LOCATION "${ASYNC_NET_DIR}/build/libasync_net.a"
        INTERFACE_INCLUDE_DIRECTORIES "${ASYNC_NET_DIR}/include"
)

# Propagate async_net compile definitions
get_target_property(_async_net_defs async_net INTERFACE_COMPILE_DEFINITIONS)

# Find SSL backend (needed by async_net for DTLS/P2P)
set(_VCPKG_HINTS "")
if(DEFINED _VCPKG_INSTALLED_DIR AND DEFINED VCPKG_TARGET_TRIPLET)
    list(APPEND _VCPKG_HINTS
        "${_VCPKG_INSTALLED_DIR}/${VCPKG_TARGET_TRIPLET}"
        "${_VCPKG_INSTALLED_DIR}/${VCPKG_TARGET_TRIPLET}/debug")
endif()

# Try to find wolfSSL first, then OpenSSL
find_package(wolfssl CONFIG QUIET HINTS ${_VCPKG_HINTS})
if(NOT wolfssl_FOUND)
    find_package(AWS-LC CONFIG QUIET HINTS ${_VCPKG_HINTS})
    if(NOT AWS-LC_FOUND)
        find_package(OpenSSL CONFIG QUIET HINTS ${_VCPKG_HINTS})
        if(NOT OpenSSL_FOUND)
            find_package(OpenSSL)
        endif()
    endif()
endif()

# Find ngtcp2 (optional, for HTTP/3)
find_package(ngtcp2 CONFIG QUIET HINTS ${_VCPKG_HINTS})

# Find protobuf (optional, for gRPC)
find_package(protobuf CONFIG QUIET HINTS ${_VCPKG_HINTS})
if(NOT protobuf_FOUND)
    find_package(Protobuf QUIET)
endif()

# ============================================================
# Protobuf code generation
# ============================================================
if(protobuf_FOUND)
    message(STATUS "protobuf found, enabling protocol compatibility")
    set(EASYTIER_PROTO_SRCS)
    set(EASYTIER_PROTO_HDRS)
    set(_PROTO_FILES
        proto/error.proto
        proto/common.proto
        proto/peer_rpc.proto
    )
    # Build absolute paths for protoc
    set(_PROTO_ABS_FILES)
    foreach(_proto ${_PROTO_FILES})
        list(APPEND _PROTO_ABS_FILES "${CMAKE_CURRENT_SOURCE_DIR}/${_proto}")
    endforeach()
    # Generate C++ sources from .proto files
    foreach(_proto ${_PROTO_FILES})
        get_filename_component(_proto_name ${_proto} NAME_WE)
        list(APPEND EASYTIER_PROTO_SRCS "${CMAKE_CURRENT_BINARY_DIR}/${_proto_name}.pb.cc")
        list(APPEND EASYTIER_PROTO_HDRS "${CMAKE_CURRENT_BINARY_DIR}/${_proto_name}.pb.h")
    endforeach()
    add_custom_command(
        OUTPUT ${EASYTIER_PROTO_SRCS} ${EASYTIER_PROTO_HDRS}
        COMMAND protobuf::protoc
            --cpp_out=${CMAKE_CURRENT_BINARY_DIR}
            --proto_path=${CMAKE_CURRENT_SOURCE_DIR}/proto
            ${_PROTO_ABS_FILES}
        WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}
        DEPENDS ${_PROTO_FILES}
        COMMENT "Generating protobuf C++ sources"
    )
    set(EASYTIER_PROTO_TARGET easytier_proto_gen)
    add_custom_target(${EASYTIER_PROTO_TARGET} DEPENDS ${EASYTIER_PROTO_SRCS} ${EASYTIER_PROTO_HDRS})
else()
    message(WARNING "protobuf not found, protocol compatibility disabled")
    set(EASYTIER_PROTO_SRCS)
    set(EASYTIER_PROTO_TARGET "")
endif()

# ============================================================
# EasyTier library
# ============================================================
set(EASYTIER_SOURCES
    # Common
    src/common/protocol.cpp
    src/common/network_identity.cpp

    # TUN device (platform-specific)
    src/tun/tun_device.cpp

    # Registry (centralized mode)
    src/registry/registry_server.cpp
    src/registry/registry_client.cpp

    # Peer transport
    src/peer/peer_transport.cpp
    src/peer/relay_transport.cpp
    src/peer/peer_manager.cpp

    # Router
    src/route/router.cpp

    # Node
    src/node/easytier_node.cpp

    # Crypto (Phase 2)
    src/crypto/cipher.cpp
    src/crypto/key_exchange.cpp

    # NAT traversal (Phase 1)
    src/nat/stun_client.cpp
    src/nat/nat_detector.cpp
    src/nat/ice_agent.cpp

    # DHT (Phase 3)
    src/dht/routing_table.cpp
    src/dht/dht_node.cpp

    # Web API (Phase 4)
    src/web/web_api.cpp

    # Subnet proxy (Phase B)
    src/subnet/subnet_proxy.cpp

    # Multi-protocol transport (Phase C)
    src/transport/ws_transport.cpp
    src/transport/quic_transport.cpp
    src/transport/transport_manager.cpp

    # KCP reliable UDP (Phase D)
    src/kcp/kcp_session.cpp

    # RPC (protocol compatibility)
    src/rpc/rpc_server.cpp

    # Protobuf generated sources
    ${EASYTIER_PROTO_SRCS}
)

# Platform-specific TUN device sources
if(CMAKE_SYSTEM_NAME STREQUAL "Linux")
    list(APPEND EASYTIER_SOURCES src/tun/tun_linux.cpp)
elseif(CMAKE_SYSTEM_NAME STREQUAL "Darwin")
    list(APPEND EASYTIER_SOURCES src/tun/tun_darwin.cpp)
elseif(CMAKE_SYSTEM_NAME STREQUAL "Windows")
    list(APPEND EASYTIER_SOURCES src/tun/tun_windows.cpp)
elseif(CMAKE_SYSTEM_NAME STREQUAL "FreeBSD")
    list(APPEND EASYTIER_SOURCES src/tun/tun_freebsd.cpp)
else()
    # Default to Linux implementation
    list(APPEND EASYTIER_SOURCES src/tun/tun_linux.cpp)
endif()

add_library(easytier_lib STATIC ${EASYTIER_SOURCES})
target_include_directories(easytier_lib PUBLIC include ${CMAKE_CURRENT_BINARY_DIR} PRIVATE src)
target_link_libraries(easytier_lib PUBLIC async_net)
if(protobuf_FOUND)
    target_link_libraries(easytier_lib PUBLIC protobuf::libprotobuf)
    target_compile_definitions(easytier_lib PUBLIC EASYTIER_HAS_PROTOBUF=1)
    if(EASYTIER_PROTO_TARGET)
        add_dependencies(easytier_lib ${EASYTIER_PROTO_TARGET})
    endif()
endif()

# ============================================================
# Tools
# ============================================================

# Registry server
add_executable(easytier_server tools/easytier_server.cpp)
target_link_libraries(easytier_server PRIVATE easytier_lib)

# Client node
add_executable(easytier_client tools/easytier_client.cpp)
target_link_libraries(easytier_client PRIVATE easytier_lib)

# Connection test tool
add_executable(test_connect tools/test_connect.cpp)
target_link_libraries(test_connect PRIVATE easytier_lib)
