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
# EasyTier library
# ============================================================
set(EASYTIER_SOURCES
    # Common
    src/common/protocol.cpp

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
target_include_directories(easytier_lib PUBLIC include PRIVATE src)
target_link_libraries(easytier_lib PUBLIC async_net)

# ============================================================
# Tools
# ============================================================

# Registry server
add_executable(easytier_server tools/easytier_server.cpp)
target_link_libraries(easytier_server PRIVATE easytier_lib)

# Client node
add_executable(easytier_client tools/easytier_client.cpp)
target_link_libraries(easytier_client PRIVATE easytier_lib)
