#!/bin/bash
# Convenience wrapper that runs the actual build script in the flatpak directory
cd "$(dirname "$0")/flatpak" && ./build-flatpak.sh
