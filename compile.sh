#!/bin/bash
# For compiling libimobiledevice, libirecovery, and idevicerestore for Linux/Windows

export PKG_CONFIG_PATH=/usr/local/lib/pkgconfig:/usr/lib/x86_64-linux-gnu/pkgconfig
export JNUM="-j$(nproc)"

rm -rf tmp
mkdir bin tmp 2>/dev/null
cd tmp

set -e

sslver="1.1.1w"
if [[ $OSTYPE == "linux"* ]]; then
    platform="linux"
    echo "* Platform: Linux"
    if [[ ! -f "/etc/lsb-release" && ! -f "/etc/debian_version" ]]; then
        echo "[Error] Ubuntu/Debian only"
        exit 1
    fi

    # based on Cryptiiiic's futurerestore static linux compile script
    export DIR=$(pwd)
    export FR_BASE="$DIR"
    if [[ $(uname -m) == "a"* ]]; then
        export CC_ARGS="CC=/usr/bin/gcc CXX=/usr/bin/g++ LD=/usr/bin/ld RANLIB=/usr/bin/ranlib AR=/usr/bin/ar"
        export ALT_CC_ARGS="CC=/usr/bin/gcc CXX=/usr/bin/g++ LD=/usr/bin/ld RANLIB=/usr/bin/ranlib AR=/usr/bin/ar"
    else
        export CC_ARGS="CC=/usr/bin/clang-14 CXX=/usr/bin/clang++-14 LD=/usr/bin/ld64.lld-14 RANLIB=/usr/bin/ranlib AR=/usr/bin/ar"
        export ALT_CC_ARGS="CC=/usr/bin/clang-14 CXX=/usr/bin/clang++-14 LD=/usr/bin/ld.lld-14 RANLIB=/usr/bin/ranlib AR=/usr/bin/ar"
    fi
    export CONF_ARGS="--disable-dependency-tracking --disable-silent-rules --prefix=/usr/local --disable-shared --enable-debug --without-cython"
    export ALT_CONF_ARGS="--disable-dependency-tracking --disable-silent-rules --prefix=/usr/local"
    if [[ $(uname -m) == "a"* && $(getconf LONG_BIT) == 64 ]]; then
        export LD_ARGS="-Wl,--allow-multiple-definition -L/usr/lib/aarch64-linux-gnu -lzstd -llzma -lbz2"
    elif [[ $(uname -m) == "a"* ]]; then
        export LD_ARGS="-Wl,--allow-multiple-definition -L/usr/lib/arm-linux-gnueabihf -lzstd -llzma -lbz2"
    else
        export LD_ARGS="-Wl,--allow-multiple-definition -L/usr/lib/x86_64-linux-gnu -lzstd -llzma -lbz2"
    fi

    echo "If prompted, enter your password"
    sudo echo -n ""
    echo "Compiling..."

    echo "Setting up build location and permissions"
    sudo rm -rf $FR_BASE || true
    sudo mkdir $FR_BASE
    sudo chown -R $USER:$USER $FR_BASE
    sudo chown -R $USER:$USER /usr/local
    sudo chown -R $USER:$USER /lib/udev/rules.d
    cd $FR_BASE
    echo "Done"

    echo "Downloading apt deps"
    sudo apt update
    sudo apt install -y aria2 curl build-essential checkinstall git autoconf automake libtool-bin pkg-config cmake zlib1g-dev libbz2-dev libusb-1.0-0-dev libusb-dev libpng-dev libreadline-dev libcurl4-openssl-dev libzstd-dev python3-dev libssl-dev autopoint
    if [[ $(uname -m) != "a"* ]]; then
        curl -LO https://apt.llvm.org/llvm.sh
        chmod 0755 llvm.sh
        sudo ./llvm.sh 14
    fi
    echo "Done"

    echo "Cloning git repos and other deps"
    git clone https://github.com/lzfse/lzfse
    git clone https://github.com/LukeeGD/libplist
    git clone https://github.com/LukeeGD/libimobiledevice-glue
    git clone https://github.com/LukeeGD/libusbmuxd
    git clone https://github.com/LukeeGD/libimobiledevice
    git clone https://github.com/LukeeGD/libirecovery
    git clone --filter=blob:none https://github.com/nih-at/libzip
    #git clone https://github.com/curl/curl
    #aria2c https://www.openssl.org/source/openssl-$sslver.tar.gz
    aria2c https://sourceware.org/pub/bzip2/bzip2-1.0.8.tar.gz
    aria2c https://github.com/facebook/zstd/releases/download/v1.5.2/zstd-1.5.2.tar.gz
    aria2c https://github.com/Mbed-TLS/mbedtls/releases/download/mbedtls-3.6.2/mbedtls-3.6.2.tar.bz2

    : '
    echo "Building openssl..."
    tar -zxvf openssl-$sslver.tar.gz
    cd openssl-$sslver
    if [[ $(uname -m) == "a"* && $(getconf LONG_BIT) == 64 ]]; then
        env $CC_ARGS ./Configure no-ssl3-method linux-aarch64 "-Wa,--noexecstack -fPIC"
    elif [[ $(uname -m) == "a"* ]]; then
        env $CC_ARGS ./Configure no-ssl3-method linux-generic32 "-Wa,--noexecstack -fPIC"
    else
        env $CC_ARGS ./Configure no-ssl3-method enable-ec_nistp_64_gcc_128 linux-x86_64 "-Wa,--noexecstack -fPIC"
    fi
    make $JNUM depend $CC_ARGS
    make $JNUM $CC_ARGS
    make install_sw install_ssldirs
    rm -rf /usr/local/lib/libcrypto.so* /usr/local/lib/libssl.so*
    cd ..
    
    if [[ $1 == "limd" ]]; then
        sudo apt remove -y libssl-dev || true
        echo "Building mbedtls..."
        bzip2 -d mbedtls-3.6.2.tar.bz2
        tar -xvf mbedtls-3.6.2.tar
        cd mbedtls-3.6.2
        make $JNUM
        make $JNUM install
        MBEDTLS_ARGS="--without-openssl --with-mbedtls"
    fi
    '

    echo "Building lzfse..."
    cd $FR_BASE
    cd lzfse
    make $JNUM $ALT_CC_ARGS
    make $JNUM install

    echo "Building libplist..."
    cd $FR_BASE
    cd libplist
    ./autogen.sh $CONF_ARGS $CC_ARGS
    make $JNUM
    make $JNUM install

    echo "Building libimobiledevice-glue..."
    cd $FR_BASE
    cd libimobiledevice-glue
    ./autogen.sh $CONF_ARGS $CC_ARGS
    make $JNUM
    make $JNUM install

    echo "Building libusbmuxd..."
    cd $FR_BASE
    cd libusbmuxd
    ./autogen.sh $CONF_ARGS $CC_ARGS
    make $JNUM
    make $JNUM install

    echo "Building libimobiledevice..."
    cd $FR_BASE
    cd libimobiledevice
    ./autogen.sh $CONF_ARGS $MBEDTLS_ARGS $CC_ARGS LIBS="-L/usr/local/lib -lz -ldl"
    make $JNUM
    make $JNUM install

    echo "Building libirecovery..."
    cd $FR_BASE
    cd libirecovery
    ./autogen.sh $CONF_ARGS $CC_ARGS
    make $JNUM
    make $JNUM install

    : '
    echo "Building curl..."
    cd $FR_BASE
    cd curl
    git checkout curl-8_11_0
    autoreconf -vi
    ./configure -C --disable-debug --disable-dependency-tracking --with-mbedtls --without-libpsl ${CC_ARGS} CFLAGS="-fPIC" LDFLAGS="$LD_ARGS -L/usr/local/lib"
    make ${JNUM} ${LNUM} ${CC_ARGS} CFLAGS="-fPIC" CXXFLAGS="-fPIC" LDFLAGS="${LD_ARGS}"
    make install | true
    rm -rf /usr/local/lib/libcurl.la
    '
    echo "Building libzip..."
    cd $FR_BASE
    cd libzip
    sed -i 's/\"Build shared libraries\" ON/\"Build shared libraries\" OFF/g' CMakeLists.txt
    cmake $CC_ARGS .
    make $JNUM
    make $JNUM install

    echo "Building libbz2..."
    cd $FR_BASE
    tar -zxvf bzip2-1.0.8.tar.gz
    cd bzip2-1.0.8
    make $JNUM
    make $JNUM install

    if [[ $1 == "limd" ]]; then
        cd $FR_BASE
        #git clone --filter=blob:none https://github.com/tukaani-project/xz
        git clone --filter=blob:none https://github.com/GNOME/libxml2
        git clone https://github.com/LukeeGD/libideviceactivation
        git clone https://github.com/LukeeGD/ideviceinstaller
        : '
        echo "Building xz..."
        cd $FR_BASE
        cd xz
        git checkout v5.8.1
        ./autogen.sh --no-po4a
        ./configure --enable-static --disable-shared
        make $JNUM
        make $JNUM install
        rm -rf /usr/local/lib/liblzma.so*
        '
        echo "Building libxml2..."
        cd $FR_BASE
        cd libxml2
        git checkout v2.11.0
        mkdir build
        cd build
        cmake .. -D BUILD_SHARED_LIBS=OFF -D LIBXML2_WITH_LZMA=OFF
        make $JNUM
        make $JNUM install

        echo "Building libideviceactivation..."
        cd $FR_BASE
        cd libideviceactivation
        ./autogen.sh $CONF_ARGS $CC_ARGS LDFLAGS="-lz"
        make $JNUM
        make $JNUM install

        echo "Building ideviceinstaller..."
        cd $FR_BASE
        cd ideviceinstaller
        ./autogen.sh $ALT_CONF_ARGS $CC_ARGS LDFLAGS="$LD_ARGS" LIBS="-L/usr/local/lib -lz -ldl"
        make $JNUM
        make $JNUM install

        cd $FR_BASE
        cd ..
        mkdir bin/libimobiledevice
        cp /usr/local/bin/i* bin/libimobiledevice/
        exit
    fi

    echo "Building idevicerestore!"
    cd $FR_BASE
    cd ..
    ./autogen.sh $ALT_CONF_ARGS $CC_ARGS LDFLAGS="$LD_ARGS" LIBS="-ldl"
    make $JNUM
    cp src/idevicerestore bin/idevicerestore_$platform

elif [[ $OSTYPE == "msys" ]]; then
    platform="win"
    echo "* Platform: Windows MSYS2"

    STATIC=1
    # based on opa334's futurerestore compile script
    pacman -S --needed --noconfirm mingw-w64-x86_64-clang mingw-w64-x86_64-libzip mingw-w64-x86_64-brotli mingw-w64-x86_64-libpng mingw-w64-x86_64-python mingw-w64-x86_64-libunistring mingw-w64-x86_64-curl mingw-w64-x86_64-cython mingw-w64-x86_64-cmake
    pacman -S --needed --noconfirm make automake autoconf pkg-config openssl libtool m4 libidn2 git libunistring libunistring-devel python cython python-devel unzip zip
    export CC=gcc
    export CXX=g++
    export BEGIN_LDFLAGS="-Wl,--allow-multiple-definition"

    echo "Cloning git repos and other deps"
    git clone https://github.com/libimobiledevice/libplist
    git clone https://github.com/libimobiledevice/libusbmuxd
    git clone https://github.com/libimobiledevice/libimobiledevice
    git clone https://github.com/libimobiledevice/libirecovery
    git clone https://github.com/madler/zlib
    wget https://github.com/curl/curl/archive/refs/tags/curl-7_76_1.zip

    if [[ $STATIC == 1 ]]; then
        export STATIC_FLAG="--enable-static --disable-shared"
        export BEGIN_LDFLAGS="$BEGIN_LDFLAGS -all-static"

        git clone https://github.com/google/brotli
        wget https://ftp.gnu.org/gnu/libunistring/libunistring-0.9.10.tar.gz
        wget https://ftp.gnu.org/gnu/libidn/libidn2-2.3.0.tar.gz
        wget https://github.com/rockdaboot/libpsl/releases/download/0.21.1/libpsl-0.21.1.tar.gz
        wget https://sourceware.org/pub/bzip2/bzip2-1.0.8.tar.gz
        wget https://tukaani.org/xz/xz-5.2.4.tar.gz
        wget https://libzip.org/download/libzip-1.5.1.tar.gz

        echo "Building brotli..."
        cd brotli
        git reset --hard 9801a2c
        git clean -fxd
        autoreconf -fi
        ./configure $STATIC_FLAG
        make $JNUM install LDFLAGS="$BEGIN_LDFLAGS"
        sed -i'' 's|Requires.private: libbrotlicommon >= 1.0.2|Requires.private: libbrotlicommon >= 0.0.0|' /mingw64/lib/pkgconfig/libbrotlidec.pc
        sed -i'' 's|Requires.private: libbrotlicommon >= 1.0.2|Requires.private: libbrotlicommon >= 0.0.0|' /mingw64/lib/pkgconfig/libbrotlienc.pc
        cd ..

        echo "Building libunistring..."
        tar -zxvf ./libunistring-0.9.10.tar.gz
        cd libunistring-0.9.10
        autoreconf -fi
        ./configure $STATIC_FLAG
        make $JNUM install LDFLAGS="$BEGIN_LDFLAGS"
        cd ..

        echo "Building libidn2..."
        tar -zxvf ./libidn2-2.3.0.tar.gz
        cd libidn2-2.3.0
        ./configure $STATIC_FLAG
        make $JNUM install LDFLAGS="$BEGIN_LDFLAGS"
        cd ..

        echo "Building libpsl..."
        tar -zxvf libpsl-0.21.1.tar.gz
        cd libpsl-0.21.1
        ./configure $STATIC_FLAG
        make $JNUM install LDFLAGS="$BEGIN_LDFLAGS"
        cd ..

        echo "Building bzip2..."
        tar -zxvf bzip2-1.0.8.tar.gz
        cd bzip2-1.0.8
        make $JNUM install LDFLAGS="--static -Wl,--allow-multiple-definition"
        cd ..

        echo "Building zlib..."
        cd zlib
        ./configure --static
        make $JNUM install LDFLAGS="$BEGIN_LDFLAGS"
        cd ..

        echo "Building libzip..."
        tar -zxvf libzip-1.5.1.tar.gz
        cd libzip-1.5.1
        mkdir new
        cd new
        cmake .. -DBUILD_SHARED_LIBS=OFF -G"MSYS Makefiles" -DCMAKE_INSTALL_PREFIX="/mingw64" -DENABLE_COMMONCRYPTO=OFF -DENABLE_GNUTLS=OFF -DENABLE_OPENSSL=OFF -DENABLE_MBEDTLS=OFF
        make $JNUM install LDFLAGS="$BEGIN_LDFLAGS"
        cd ../..
    fi

    echo "Building curl..."
    unzip curl-7_76_1.zip -d .
    cd curl-curl-7_76_1
    autoreconf -fi
    ./configure $STATIC_FLAG --with-schannel --without-ssl
    cd lib
    make $JNUM install CFLAGS="-DCURL_STATICLIB -DNGHTTP2_STATICLIB" LDFLAGS="$BEGIN_LDFLAGS"
    cd ../..

    echo "Building libplist..."
    cd libplist
    git reset --hard 787a449
    git clean -fxd
    ./autogen.sh $STATIC_FLAG --without-cython
    make $JNUM install LDFLAGS="$BEGIN_LDFLAGS"
    cd ..

    echo "Building libusbmuxd..."
    cd libusbmuxd
    git reset --hard 3eb50a0
    git clean -fxd
    ./autogen.sh $STATIC_FLAG
    make $JNUM install LDFLAGS="$BEGIN_LDFLAGS"
    cd ..

    echo "Building libimobiledevice..."
    cd libimobiledevice
    git reset --hard ca32415
    git clean -fxd
    ./autogen.sh $STATIC_FLAG --without-cython
    make $JNUM install LDFLAGS="$BEGIN_LDFLAGS"
    cd ..

    echo "Building libirecovery..."
    cd libirecovery
    git reset --hard 4793494
    git clean -fxd
    sed -i'' 's|ret = DeviceIoControl(client->handle, 0x220195, data, length, data, length, (PDWORD) transferred, NULL);|ret = DeviceIoControl(client->handle, 0x2201B6, data, length, data, length, (PDWORD) transferred, NULL);|' src/libirecovery.c
    ./autogen.sh $STATIC_FLAG
    make $JNUM install LDFLAGS="$BEGIN_LDFLAGS -ltermcap"
    cd ..

    echo "Building idevicerestore!"
    cd ..
    ./autogen.sh $STATIC_FLAG
    if [[ $STATIC == 1 ]]; then
        export curl_LIBS="$(curl-config --static-libs)"
        make $JNUM install CFLAGS="-DCURL_STATICLIB" LDFLAGS="$BEGIN_LDFLAGS" LIBS="-llzma -lbz2 -lbcrypt"
    else
        make $JNUM install LDFLAGS="$BEGIN_LDFLAGS"
    fi
    cp /mingw64/bin/idevicerestore bin/idevicerestore_$platform
fi

echo "Done!"
