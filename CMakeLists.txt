# Specify the minimum version for CMake
CMAKE_MINIMUM_REQUIRED(VERSION 3.2)

# Project's name 
PROJECT(OPRF)

FIND_PACKAGE(OpenSSL REQUIRED)
find_package(OpenMP REQUIRED)
find_package(libOTe REQUIRED)

SET(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -std=c++14  -mavx -mavx2  -fpic -flto -Wno-deprecated-declarations -Wno-unused-result -Xpreprocessor -O3 -DNDEBUG -march=native -Wall -Wfatal-errors")
# SET(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -std=c++14  -mavx -mavx2 -g -DNDEBUG -fpic -flto -Wno-deprecated-declarations -Wno-unused-result -Xpreprocessor -march=native -Wall -Wfatal-errors")
# SET(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -std=c++14  -g -DNDEBUG")

SET(EXECUTABLE_OUTPUT_PATH ${PROJECT_SOURCE_DIR}/build) 

ADD_EXECUTABLE(main ./test_voleoprf.cpp)

if(OpenMP_CXX_FOUND)
    target_compile_options(main PUBLIC ${OpenMP_CXX_FLAGS})
endif()
target_compile_options(main PUBLIC $<$<COMPILE_LANGUAGE:CXX>:-std=c++14> -lpthread)

TARGET_LINK_LIBRARIES(main ${OPENSSL_LIBRARIES} OpenMP::OpenMP_CXX oc::libOTe)