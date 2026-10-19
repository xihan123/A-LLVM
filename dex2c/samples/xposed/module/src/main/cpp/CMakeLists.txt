cmake_minimum_required(VERSION 3.22)
project(dex2c_coexist LANGUAGES CXX)
add_library(coexist SHARED coexist.cpp)
target_link_options(coexist PRIVATE "-Wl,-z,max-page-size=16384")
