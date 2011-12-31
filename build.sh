#! /bin/bash

XUL_VERSION="9.0.1"
XUL_SOURCE="http://ftp.mozilla.org/pub/mozilla.org/xulrunner/releases/$XUL_VERSION/sdk"

BUILDID=`date +%Y%M%d%H%M%S`

EXCLUDES="--exclude xulrunner
          --exclude updates
          --exclude mccoy.exe
          --exclude mccoy
          --exclude libmozutils.dylib
          --exclude mozutils.dll
          --exclude application.ini"

XULEXCLUDES="
  dependentlibs.list
  js.exe
  js
  xpcshell.exe
  xpcshell
  README.txt
  redit.exe
  mozilla-xremote-client
  nsinstall"

DIR=`dirname $0`
BASEDIR=`cd "$DIR"; pwd`

cd "$BASEDIR"
rm -rf build
mkdir -p build/base

tar -cC src $EXCLUDES . | tar -xC build/base
cat src/application.ini | sed -e s/^BuildID=.*$/BuildID=$BUILDID/ >build/base/application.ini

cd build

echo Building for Windows

PLATFORM=win
BASE=$PLATFORM/McCoy

mkdir -p $BASE
cp -R base/* $BASE
wget ${XUL_SOURCE}/xulrunner-${XUL_VERSION}.en-US.win32.sdk.zip -O xulrunner.zip -o /dev/null
unzip -q xulrunner.zip xulrunner-sdk/bin/*
rm xulrunner.zip
mv xulrunner-sdk/bin $BASE/xulrunner
rmdir xulrunner-sdk
cd $BASE
mv xulrunner/xulrunner-stub.exe mccoy.exe
cp xulrunner/mozutils.dll .
xulrunner/redit.exe mccoy.exe chrome/icons/default/default.ico
cd xulrunner
rm -rf $XULEXCLUDES

cd "$BASEDIR/build/$PLATFORM"
zip -r9q ../mccoy-$PLATFORM.zip *
cd ..

echo Building for Linux

PLATFORM=linux
BASE=$PLATFORM/mccoy

mkdir -p $BASE
cp -R base/* $BASE
wget ${XUL_SOURCE}/xulrunner-${XUL_VERSION}.en-US.linux-i686.sdk.tar.bz2 -O xulrunner.tar.bz2 -o /dev/null
mkdir -p $BASE/xulrunner
tar -xjf xulrunner.tar.bz2 --strip-components 2 -C $BASE/xulrunner xulrunner-sdk/bin
rm xulrunner.tar.bz2
cd $BASE
mv xulrunner/xulrunner-stub mccoy
cd xulrunner
rm -rf $XULEXCLUDES

cd "$BASEDIR/build/$PLATFORM"
tar -cjf ../mccoy-$PLATFORM.tar.bz2 *
cd ..

echo Building for OSX

PLATFORM=osx
BASE=$PLATFORM/McCoy.app

mkdir -p $BASE
cp -R ../macbuild/* $BASE
cp -R base/* $BASE/Contents/Resources
wget ${XUL_SOURCE}/xulrunner-${XUL_VERSION}.en-US.mac-i386.sdk.tar.bz2 -O xulrunner.tar.bz2 -o /dev/null
mkdir -p $BASE/Contents/Frameworks/XUL.Framework/Versions/Current
tar -xjf xulrunner.tar.bz2 --strip-components 2 -C $BASE/Contents/Frameworks/XUL.Framework/Versions/Current xulrunner-sdk/bin
rm xulrunner.tar.bz2
cd $BASE/Contents
mkdir -p MacOS
mv Frameworks/XUL.Framework/Versions/Current/xulrunner MacOS/mccoy
cp Frameworks/XUL.Framework/Versions/Current/libmozutils.dylib MacOS
cd Frameworks/XUL.Framework/Versions/Current
rm -rf $XULEXCLUDES

cd "$BASEDIR/build/$PLATFORM"
zip -r9q ../mccoy-$PLATFORM.zip *
cd ..

rm -rf base

