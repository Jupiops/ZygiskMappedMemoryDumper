#!/bin/bash

# Enable strict error handling
set -e

# Navigate to the module directory (adjust this path if necessary)
MODULE_DIR="$(dirname "$0")"
cd "$MODULE_DIR"

# Step 1: Execute ndk-build command
ndk-build -j4

# Step 2: Clean and recreate the out directory
OUT_DIR="out"
if [ -d "$OUT_DIR" ]; then
    echo "Deleting existing $OUT_DIR folder..."
    rm -rf "$OUT_DIR"
fi

echo "Creating new $OUT_DIR folder..."
mkdir -p "$OUT_DIR/zygisk"

# Step 3: Copy the contents of the libs folder to the zygisk folder in the out directory
LIBS_DIR="libs"
if [ -d "$LIBS_DIR" ]; then
    echo "Copying contents of $LIBS_DIR to $OUT_DIR/zygisk..."
    for ABI_DIR in "$LIBS_DIR"/*; do
        if [ -d "$ABI_DIR" ]; then
            ABI_NAME="$(basename "$ABI_DIR")"
            mkdir -p "$OUT_DIR/zygisk/$ABI_NAME"
            cp "$ABI_DIR"/lib*.so "$OUT_DIR/zygisk/$ABI_NAME.so"
        fi
    done
else
    echo "Error: $LIBS_DIR folder not found!"
    exit 1
fi

# Step 4: Copy the template folder to the out directory
TEMPLATE_DIR="template"
if [ -d "$TEMPLATE_DIR" ]; then
    echo "Copying $TEMPLATE_DIR folder to $OUT_DIR..."
    cp -r "$TEMPLATE_DIR/"* "$OUT_DIR/"
else
    echo "Error: $TEMPLATE_DIR folder not found!"
    exit 1
fi

# Print success message
echo "Build script executed successfully."