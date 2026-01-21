#!/bin/bash
# Build liboqs as a shared library for .NET interop on macOS

set -e  # Exit on any error

# Default values
CONFIGURATION="${1:-Release}"
OUTPUT_DIR="${2:-./src/native}"

echo "Building liboqs as shared library for .NET on macOS..."

# Get the script directory before changing directories
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"

# Create output directory
mkdir -p "$OUTPUT_DIR"

# Navigate to liboqs source
cd liboqs

# Create build directory
BUILD_DIR="build-dotnet-shared"
if [ -d "$BUILD_DIR" ]; then
    rm -rf "$BUILD_DIR"
fi
mkdir "$BUILD_DIR"

cd "$BUILD_DIR"

echo "Configuring CMake for shared library build..."

# Configure with shared library options
cmake .. \
    -DCMAKE_BUILD_TYPE="$CONFIGURATION" \
    -DBUILD_SHARED_LIBS=ON \
    -DCMAKE_POSITION_INDEPENDENT_CODE=ON \
    -DCMAKE_OSX_ARCHITECTURES=arm64 \
    -DOQS_USE_OPENSSL=OFF \
    -DOQS_BUILD_ONLY_LIB=ON \
    -DOQS_DIST_BUILD=YES \
    -DOQS_PERMIT_UNSUPPORTED_ARCHITECTURE=ON \
    -DOQS_ENABLE_KEM_ML_KEM=ON \
    -DOQS_ENABLE_KEM_KYBER=ON \
    -DOQS_ENABLE_KEM_FRODOKEM=ON \
    -DOQS_ENABLE_KEM_BIKE=ON \
    -DOQS_ENABLE_KEM_HQC=ON \
    -DOQS_ENABLE_KEM_NTRU=ON \
    -DOQS_ENABLE_KEM_NTRUPRIME=ON \
    -DOQS_ENABLE_KEM_CLASSIC_MCELIECE=ON \
    -DOQS_ENABLE_SIG_ML_DSA=ON \
    -DOQS_ENABLE_SIG_FALCON=ON \
    -DOQS_ENABLE_SIG_SLH_DSA=ON \
    -DOQS_ENABLE_SIG_SPHINCS=ON \
    -DOQS_ENABLE_SIG_MAYO=ON \
    -DOQS_ENABLE_SIG_CROSS=ON \
    -DOQS_ENABLE_SIG_UOV=ON \
    -DOQS_ENABLE_SIG_SNOVA=ON

echo "Building liboqs..."
cmake --build . --config "$CONFIGURATION"

# Find the built shared library
DYLIB_PATH=$(find . -name "liboqs*.dylib" -type f | head -n 1)
if [ -z "$DYLIB_PATH" ]; then
    # Try in lib directory for different build layouts
    DYLIB_PATH=$(find lib -name "liboqs*.dylib" -type f 2>/dev/null | head -n 1)
fi

if [ -n "$DYLIB_PATH" ]; then
    # Use the script directory calculated at the beginning
    TARGET_PATH="$SCRIPT_DIR/$OUTPUT_DIR"
    # Ensure target directory exists
    mkdir -p "$TARGET_PATH"
    
    # Copy and rename to consistent name liboqs.dylib
    cp "$DYLIB_PATH" "$TARGET_PATH/liboqs.dylib"
    DYLIB_BASENAME=$(basename "$DYLIB_PATH")
    
    echo "Successfully copied and renamed $DYLIB_BASENAME to liboqs.dylib in $TARGET_PATH"
else
    echo "Warning: Could not find liboqs.dylib in build output"
    echo "Build contents:"
    find . -type f -name "*.dylib*" -o -name "*.so*" -o -name "*.dll" | head -20
fi

echo "Build complete!"
