#!/bin/bash
# Build liboqs as a shared library for .NET interop on Linux

set -e  # Exit on any error

# Default values
CONFIGURATION="${1:-Release}"
OUTPUT_DIR="${2:-./src/native}"

echo "Building liboqs as shared library for .NET on Linux..."

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
    -DOQS_BUILD_ONLY_LIB=ON \
    -DOQS_DIST_BUILD=YES \
    -DOQS_PERMIT_UNSUPPORTED_ARCHITECTURE=ON \
    -DOQS_ENABLE_KEM_ML_KEM=ON \
    -DOQS_ENABLE_KEM_KYBER=ON \
    -DOQS_ENABLE_KEM_FRODOKEM=ON \
    -DOQS_ENABLE_SIG_ML_DSA=ON \
    -DOQS_ENABLE_SIG_DILITHIUM=ON \
    -DOQS_ENABLE_SIG_FALCON=ON

echo "Building liboqs..."
cmake --build . --config "$CONFIGURATION"

# Find the built shared library
SO_PATH=$(find . -name "liboqs.so*" -type f | head -n 1)
if [ -z "$SO_PATH" ]; then
    # Try in src directory for different build layouts
    SO_PATH=$(find src -name "liboqs.so*" -type f 2>/dev/null | head -n 1)
fi

if [ -n "$SO_PATH" ]; then
    # Use the script directory calculated at the beginning
    TARGET_PATH="$SCRIPT_DIR/$OUTPUT_DIR"
    # Ensure target directory exists
    mkdir -p "$TARGET_PATH"
    
    # Copy the shared library and create a symlink with simple name
    cp "$SO_PATH" "$TARGET_PATH/"
    
    # Create a symlink with the simple name liboqs.so if it has version numbers
    SO_BASENAME=$(basename "$SO_PATH")
    if [ "$SO_BASENAME" != "liboqs.so" ]; then
        ln -sf "$SO_BASENAME" "$TARGET_PATH/liboqs.so"
        echo "Created symlink liboqs.so -> $SO_BASENAME"
    fi
    
    echo "Successfully copied $SO_BASENAME to $TARGET_PATH"
    
    # Also copy to example directory for testing
    EXAMPLE_DIR="$SCRIPT_DIR/src/Examples/bin/Debug/net9.0"
    if [ -d "$EXAMPLE_DIR" ]; then
        cp "$SO_PATH" "$EXAMPLE_DIR/"
        if [ "$SO_BASENAME" != "liboqs.so" ]; then
            ln -sf "$SO_BASENAME" "$EXAMPLE_DIR/liboqs.so"
        fi
        echo "Copied $SO_BASENAME to examples directory"
    fi
else
    echo "Warning: Could not find liboqs.so in build output"
    echo "Build contents:"
    find . -type f -name "*.so*" -o -name "*.dylib" -o -name "*.dll" | head -20
fi

echo "Build complete!"
