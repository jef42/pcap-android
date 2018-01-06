LOCAL_PATH := $(call my-dir)
include $(CLEAR_VARS)
LOCAL_MODULE := monitor_user
LOCAL_SRC_FILES := ../monitor_user.c \
   ../../lib_src/get_num.c \
   ../../lib_src/help_ip.c \
   ../../pcap_src/pcap-linux.c \
   ../../pcap_src/pcap-usb-linux.c \
   ../../pcap_src/pcap-netfilter-linux.c \
   ../../pcap_src/pcap.c \
   ../../pcap_src/fad-getad.c \
   ../../pcap_src/ifaddrs.c \
   ../../pcap_src/inet.c \
   ../../pcap_src/fad-helpers.c \
   ../../pcap_src/gencode.c \
   ../../pcap_src/optimize.c \
   ../../pcap_src/nametoaddr.c \
   ../../pcap_src/etherent.c \
   ../../pcap_src/savefile.c \
   ../../pcap_src/sf-pcap.c \
   ../../pcap_src/sf-pcap-ng.c \
   ../../pcap_src/pcap-common.c \
   ../../pcap_src/bpf_image.c \
   ../../pcap_src/bpf_dump.c \
   ../../pcap_src/scanner.c \
   ../../pcap_src/grammar.c \
   ../../pcap_src/bpf_filter.c \
   ../../pcap_src/version.c

LOCAL_CFLAGS := -DSYS_ANDROID=1 -Dyylval=pcap_lval -DHAVE_CONFIG_H -D_U_="__attribute((unused))" -I$(LOCAL_PATH)/../../pcap_src -I$(LOCAL_PATH)/../../lib_src
include $(BUILD_EXECUTABLE)
