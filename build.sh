#!/bin/sh
# usage: ./build.sh        -> build/reflectorv2.jar
#        ./build.sh test   -> compile + run the offline test suite
set -e
cd "$(dirname "$0")"
if command -v javac >/dev/null 2>&1; then JAVAC=javac; else JAVAC="java com.sun.tools.javac.Main"; fi
rm -rf build && mkdir -p build/classes
$JAVAC -nowarn -source 11 -target 11 -d build/classes src/burp/*.java
if [ "$1" = "test" ]; then
  $JAVAC -nowarn -source 11 -target 11 -cp build/classes -d build/classes test/ReflectorTest.java
  exec java -cp build/classes burp.ReflectorTest
fi
jar cf build/reflectorv2.jar -C build/classes . 2>/dev/null || (cd build/classes && python3 -c "import shutil;shutil.make_archive('../reflectorv2','zip','.')" && mv ../reflectorv2.zip ../reflectorv2.jar)
echo "built build/reflectorv2.jar"
