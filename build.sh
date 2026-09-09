#!/bin/bash

# Save as build.sh
case "$1" in
  "ios")
    ./build_ios.sh
    ;;
  "android")
    ./build_android.sh
    ;;
  "python")
    ./build_python.sh
    ;;
  "desktop")
    # The JNA-loadable cdylibs a desktop JVM client needs (loopky#54). Takes its own argument:
    # ./build.sh desktop linux | macos | all
    ./build_desktop.sh "${2:-all}"
    ;;
  "all")
    ./build_ios.sh && ./build_android.sh && ./build_python.sh
    ;;
  *)
    echo "Usage: $0 {ios|android|python|desktop|all}"
    echo "       $0 desktop {linux|macos|all}"
    exit 1
    ;;
esac