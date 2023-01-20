#!/bin/bash



#!!!!!!!!!!!  test libuv with or without sudo
#compile external libs and copy to ./external/libs folder
set -e
TMPFOLDER=/tmp/uv

CURRENTFOLDER=$(pwd)
DESTFOLDER=$(pwd)/libs
rm -rf $TMPFOLDER
mkdir -p $TMPFOLDER

#######  install openssl with static option
cd $CURRENTFOLDER
cp openssl-1.1.1o.tar.gz $TMPFOLDER
cd $TMPFOLDER
tar zxvf openssl-1.1.1o.tar.gz 
cd openssl-1.1.1o
if [[ "$OSTYPE" == "darwin"* ]]; then
./config  --prefix=$DESTFOLDER
else 
./config -static --static --prefix=$DESTFOLDER
fi
make
make install
if [[ "$OSTYPE" == "darwin"* ]]; then
rm $DESTFOLDER/lib/*.dylib
fi



if [[ ! "$OSTYPE" == "darwin"* ]]; then
####### install cmocka ############
cd $CURRENTFOLDER
cp cmocka-1.1.5.tar.xz $TMPFOLDER
cd $TMPFOLDER
tar xvf cmocka-1.1.5.tar.xz
cd cmocka-1.1.5
rm -rf CMakeCache.txt
mkdir -p build
cd build
cmake -DCMAKE_INSTALL_PREFIX=$DESTFOLDER -DCMAKE_BUILD_TYPE=Debug ../
make
make install
fi


######### install hiredis ############
cd $CURRENTFOLDER
cp hiredis-1.0.2.zip $TMPFOLDER
cd $TMPFOLDER
unzip hiredis-1.0.2.zip
cd hiredis-1.0.2
export PREFIX=$DESTFOLDER
make
make install
if [[ "$OSTYPE" == "darwin"* ]]; then
rm $DESTFOLDER/lib/*.dylib
fi