# Fixture project for the dynamic layer.
#
# Each program commits exactly one defect, because the sanitizers are built
# with -fno-sanitize-recover: the first report ends the process, so a program
# with two defects would only ever demonstrate the first.
#
# Registered with CTest so the default --run command exercises them. They are
# expected to fail; what Kordon reads is what they printed on the way out.

cmake_minimum_required(VERSION 3.16)
project(kordon_dynamic_fixture CXX)
set(CMAKE_CXX_STANDARD 17)
enable_testing()

foreach(probe leak use_after_free heap_overflow signed_overflow uninitialised)
    add_executable(${probe} ${probe}.cpp)
    add_test(NAME ${probe} COMMAND ${probe})
endforeach()
