cmake_minimum_required(VERSION 3.30)

#set(CMAKE_TOOLCHAIN_FILE "${VCPKG_ROOT}/scripts/buildsystems/vcpkg.cmake")
set(CMAKE_TOOLCHAIN_FILE "E:/SDK/vcpkg/vcpkg/scripts/buildsystems/vcpkg.cmake")

project(DDNS_cpp)

set(CMAKE_CXX_STANDARD 23)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

if (WIN32)
    include_directories(include)
    link_directories(libs)


    include(FetchContent)

    FetchContent_Declare(
            yaml-cpp
            GIT_REPOSITORY https://github.com/jbeder/yaml-cpp.git
            GIT_TAG 0.8.0 # Can be a tag (yaml-cpp-x.x.x), a commit hash, or a branch name (master)
    )
    FetchContent_MakeAvailable(yaml-cpp)

    set(SOURCES main.cpp
            src/SSHOpenWRTGetIp.cpp
            include/SSHOpenWRTGetIp.h
            src/native.cpp
            src/GetTheLocalIP.cpp
            include/GetTheLocalIP.h
            src/YamlConfig.cpp
            include/YamlConfig.h
            src/NetworkRequest.cpp
            include/NetworkRequest.h
            src/DDNSWorker.cpp
            include/DDNSWorker.h
            src/AliCloudReport.cpp
            include/AliCloudReport.h
            src/GLog.cpp
            include/GLog.h
            src/ICloudReport.cpp
            include/ICloudReport.h)


    add_executable(DDNS_cpp ${SOURCES})

    target_link_libraries(DDNS_cpp PRIVATE ws2_32 iphlpapi libssh2 libcrypto libssl)
    target_link_libraries(DDNS_cpp PUBLIC yaml-cpp::yaml-cpp) # The library or executable that require yaml-cpp library

    file(GLOB DATA_FILE ${CMAKE_CURRENT_SOURCE_DIR}/dll/*.dll)
    file(COPY ${DATA_FILE}
            DESTINATION ${CMAKE_CURRENT_BINARY_DIR}/)

    file(COPY ${CMAKE_CURRENT_SOURCE_DIR}/config/config.yaml
            DESTINATION ${CMAKE_CURRENT_BINARY_DIR}/config/)
endif ()