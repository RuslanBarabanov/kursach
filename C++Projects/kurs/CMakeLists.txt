cmake_minimum_required(VERSION 3.10)
project(ServerTests)

set(CMAKE_CXX_STANDARD 11)

# Находим CryptoPP
find_package(PkgConfig REQUIRED)
pkg_check_modules(CRYPTOPP REQUIRED libcrypto++)

# Исходные файлы
set(SERVER_SOURCES
    server.cpp
    test_server.cpp
)

# Исполняемый файл тестов
add_executable(server_tests ${SERVER_SOURCES})
target_include_directories(server_tests PRIVATE ${CMAKE_SOURCE_DIR})
target_link_libraries(server_tests ${CRYPTOPP_LIBRARIES})
target_compile_options(server_tests PRIVATE ${CRYPTOPP_CFLAGS_OTHER})

# Цель для запуска тестов
add_custom_target(test_server
    COMMAND ./server_tests
    DEPENDS server_tests
    COMMENT "Running server unit tests..."
)
