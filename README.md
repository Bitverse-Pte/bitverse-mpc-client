# bitverse-mpc-client

Client MPC dynamic library is a fully functional client application of a minimalist decentralized HD wallet using 2 party ECDSA.
Fork from [ZenGo-X](https://github.com/ZenGo-X/gotham-city).

# Disclaimer
USE AT YOUR OWN RISK, we are not responsible for software/hardware and/or any transactional issues that may occur while using Client MPC dynamic library.

# Project Status

The project is currently work in progress. For more information you can [email](developer@bitverse.zone) us.

## Getting started

- build
```shell
cargo build --release
```
ios
```shell
cargo lipo --release
cargo +nightly build -Z build-std --target aarch64-apple-ios-sim
```

## Cross Compile
```cargo.toml
[target.aarch64-linux-android]
ar = "/dev/NDK/arm64/bin/aarch64-linux-android-ar"
linker = "/dev/NDK/arm64/bin/aarch64-linux-android-clang"

[target.armv7-linux-androideabi]
ar = "/dev/NDK/arm/bin/arm-linux-androideabi-ar"
linker = "/dev/NDK/arm/bin/arm-linux-androideabi-clang"

[target.i686-linux-android]
ar = "/dev/NDK/x86/bin/i686-linux-android-ar"
linker = "/dev/NDK/x86/bin/i686-linux-android-clang"
[target.x86_64-linux-android]
ar = "/dev/NDK/x86_64/bin/x86_64-linux-android-ar"
linker = "/dev/NDK/x86_64/bin/x86_64-linux-android-clang"


```

 ```shell
 
export NDK_HOME=/Users/sh00338ml/Library/Android/sdk/ndk/22.1.7171670
${NDK_HOME}/build/tools/make_standalone_toolchain.py --api 23 --arch arm64 --install-dir NDK/arm64
${NDK_HOME}/build/tools/make_standalone_toolchain.py --api 23 --arch arm --install-dir NDK/arm
${NDK_HOME}/build/tools/make_standalone_toolchain.py --api 23 --arch x86 --install-dir NDK/x86
${NDK_HOME}/build/tools/make_standalone_toolchain.py --api 23 --arch x86_64 --install-dir NDK/x86_64
 
 
 export PROJECT_NDK_HOME=/Users/sh00338ml/dev
 export PATH=${PATH}:"${PROJECT_NDK_HOME}/NDK/arm64/bin":"${PROJECT_NDK_HOME}/NDK/arm/bin":"${PROJECT_NDK_HOME}/NDK/x86/bin":"${PROJECT_NDK_HOME}/NDK/x86_64/bin"
 export OPENSSL_DIR=/opt/homebrew/Cellar/openssl@1.1/1.1.1o

 ```

- .h
```shell
cbindgen  -c cbindgen.toml > target/bindings.h
```

- build
```shell

cargo clean
cargo build --release
cargo build --target x86_64-linux-android --release
cargo build --target i686-linux-android --release
cargo build --target armv7-linux-androideabi --release
cargo build --target aarch64-linux-android --release
```
ios
```shell
cargo clean
cargo lipo --release
cargo +nightly build -Z build-std --target aarch64-apple-ios-sim --release
cargo +nightly build -Z build-std --target armv7s-apple-ios --release
cargo +nightly build -Z build-std --target armv7-apple-ios --release
cargo +nightly build -Z build-std --target i386-apple-ios --release

lipo -create \
  target/universal/release/libbw_mpc_client.a \
  target/armv7-apple-ios/release/libbw_mpc_client.a \
  -output libbw_mpc_client.a
```

# reference
[mac cross compile](https://gist.github.com/surpher/bbf88e191e9d1f01ab2e2bbb85f9b528)

# License
Curv is released under the terms of the MIT license. See LICENSE for more information.

# Development Process & Contact
This library is maintained by Bitverse-Pte. Contributions are highly welcomed! Besides GitHub issues and PRs, feel free to reach out by mail or join Bitverse [Telegram](https://t.me/eventguessingBitversecommunity) for discussions on code and research.