cmake_minimum_required(VERSION 3.5)
project(detect_network)

set(CMAKE_C_COMPILER clang)
set(CMAKE_CXX_COMPILER clang++)

set(CMAKE_C_FLAGS "-pthread -g -DDEBUG_LOG -DHAVE_CONFIG_H -D_U_=\"__attribute((unused))\"")

include_directories(../../pcap_src)
include_directories(../../lib_src)

set(SOURCES ../detect_network.c
            ../../lib_src/get_num.c
            ../../lib_src/help_ip.c
            ../../pcap_src/pcap-linux.c
            ../../pcap_src/pcap-usb-linux.c
            ../../pcap_src/pcap.c
            ../../pcap_src/fad-getad.c
            ../../pcap_src/inet.c
            ../../pcap_src/fad-helpers.c
            ../../pcap_src/gencode.c
            ../../pcap_src/optimize.c
            ../../pcap_src/nametoaddr.c
            ../../pcap_src/etherent.c
            ../../pcap_src/savefile.c
            ../../pcap_src/sf-pcap.c
            ../../pcap_src/sf-pcap-ng.c
            ../../pcap_src/pcap-common.c
            ../../pcap_src/bpf_image.c
            ../../pcap_src/bpf_dump.c
            ../../pcap_src/scanner.c
            ../../pcap_src/grammar.c
            ../../pcap_src/bpf_filter.c
            ../../pcap_src/version.c)

add_executable(detect_network ${SOURCES})
