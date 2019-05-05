cmake_minimum_required( VERSION 3.1 FATAL_ERROR )

project(CRYPTOJS)


set( CMAKE_CXX_STANDARD 11 )
set( CMAKE_CXX_STANDARD_REQUIRED YES )

include(ExternalProject)
ExternalProject_Add( project_secp256k1
    PREFIX ${CMAKE_CURRENT_BINARY_DIR}/secp256k1-zkp
    SOURCE_DIR ${CMAKE_CURRENT_SOURCE_DIR}/secp256k1-zkp
    CONFIGURE_COMMAND ${CMAKE_CURRENT_SOURCE_DIR}/secp256k1-zkp/configure --disable-benchmark --disable-tests --disable-exhaustive-tests --enable-module-recovery --enable-module-rangeproof --enable-module-generator --enable-experimental --with-bignum=no --with-field=32bit --with-scalar=32bit
    BUILD_COMMAND make clean && make
    INSTALL_COMMAND DESTDIR=<INSTALL_DIR> make install
    BUILD_BYPRODUCTS <BINARY_DIR>/.libs/libsecp256k1.a
    )
ExternalProject_Add_Step(project_secp256k1 autogen
    WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}/secp256k1-zkp
    COMMAND ${CMAKE_CURRENT_SOURCE_DIR}/secp256k1-zkp/autogen.sh
    DEPENDERS configure
    )

ExternalProject_Get_Property(project_secp256k1 INSTALL_DIR)
ExternalProject_Get_Property(project_secp256k1 SOURCE_DIR)
#    file(MAKE_DIRECTORY ${INSTALL_DIR}/usr/local/include)
add_library(secp256k1 STATIC IMPORTED)
set_target_properties(secp256k1 PROPERTIES
    IMPORTED_LOCATION "${INSTALL_DIR}/usr/local/lib/libsecp256k1.a"
    INTERFACE_INCLUDE_DIRECTORIES "${SOURCE_DIR}/include"
    )

add_dependencies(secp256k1 project_secp256k1)

ExternalProject_Add( project_cryptopp
    PREFIX ${CMAKE_CURRENT_BINARY_DIR}/cryptopp
    SOURCE_DIR ${CMAKE_CURRENT_SOURCE_DIR}/cryptopp
    CONFIGURE_COMMAND cmake <SOURCE_DIR> -DCMAKE_BUILD_TYPE=Release -DBUILD_SHARED=OFF -DBUILD_TESTING=OFF -DCMAKE_INSTALL_PREFIX=<INSTALL_DIR>
#    BUILD_IN_SOURCE 1
    BUILD_COMMAND make static
    INSTALL_COMMAND make install
    BUILD_BYPRODUCTS <BINARY_DIR>/libcryptopp.a
    )

ExternalProject_Add_Step(project_cryptopp merge_cryptopp_cmake
    WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}/cryptopp
    COMMAND cp ${CMAKE_CURRENT_SOURCE_DIR}/cryptopp-cmake/CMakeLists.txt . && cp ${CMAKE_CURRENT_SOURCE_DIR}/cryptopp-cmake/cryptopp-config.cmake .
    DEPENDERS configure
    )

ExternalProject_Get_Property(project_cryptopp INSTALL_DIR)
ExternalProject_Get_Property(project_cryptopp SOURCE_DIR)
file(MAKE_DIRECTORY ${INSTALL_DIR}/include)
add_library(cryptopp STATIC IMPORTED)
set_target_properties(cryptopp PROPERTIES
    IMPORTED_LOCATION "${INSTALL_DIR}/lib/libcryptopp.a"
    INTERFACE_INCLUDE_DIRECTORIES "${INSTALL_DIR}/include"
    )

add_dependencies(cryptopp project_cryptopp)


if(JS)
    add_executable(cryptojs "main.cpp")
    set(CMAKE_EXECUTABLE_SUFFIX ".js")
    # -s MODULARIZE=1 -s EXPORT_NAME='CryptoJS'
    set_target_properties(cryptojs PROPERTIES LINK_FLAGS "-O3 -s WASM=1 -s BINARYEN_METHOD='native-wasm' -s EXPORTED_FUNCTIONS='[_build_confidential_tx, _apb, _appb, _sizeofRet]' -s EXTRA_EXPORTED_RUNTIME_METHODS='[cwrap, ccall, setValue]'")
else(JS)
    add_library(cryptojs "main.cpp")
endif(JS)

target_include_directories(cryptojs PUBLIC secp256k1 cryptopp)
target_link_libraries(cryptojs PUBLIC secp256k1 cryptopp)
