#!/bin/bash

# POCO_STATIC=1 - for static build
# POCO_UNBUNDLED - for no built-in version of libs
# CMAKE_INSTALL_PREFIX=path - for install path

rm -rf cmake-build
mkdir cmake-build
cd cmake-build

PLATFORM=`uname`
if [ "$PLATFORM" = "Darwin" ]
then
	cmake ../. -DPG_VERSION=13 -DCMAKE_OSX_ARCHITECTURES="x86_64;arm64" -DCMAKE_LIBRARY_PATH="$HOME/usr/local/lib;$HOME/usr/lib;/usr/local/lib" -DADD_INCLUDE_DIRECTORIES="$HOME/usr/local/include;$HOME/usr/include;/usr/local/include" ..  $1 $2 $3 $4 $5
	make -j3
	sudo make install
else
	cmake ../. -DPG_VERSION=13  ..  $1 $2 $3 $4 $5
	make -j3
	sudo make install
fi

#rm -rf CMakeCache.txt

#cmake ../. -DCMAKE_BUILD_TYPE=Release $1 $2 $3 $4 $5
#make -j3
#make install


cd ..
