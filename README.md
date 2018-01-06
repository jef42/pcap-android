# pcap-android

Works only for rooted phones.

# Build
The projects can be build for the platforms:

- Android
- Linux

For example to build detect_network.

For Linux:

```base
cd detect_network/unix_build/
mkdir build
cd build
cmake ..
```

For Android:
```base
cd detect_network/android_build
export NDK_PROJECT_PATH=.
ndk-build NDK_APPLICATION_MK=./Application.mk
```
# Requirements:
The files are compiled with:
- gcc version 5.4.1 20160904
- ndk version 16.0.4442984

On a Ubuntu 16-04 LTS

# Usage:
Each application has the option '-h' that displays supported arguments. The applications will just generate packages, to observe results use tcpdump or wireshark.

# License
MIT