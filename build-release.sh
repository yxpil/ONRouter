#!/bin/bash
set -e

# ONRouter Cross-Platform Build Script
# Supports: Linux, macOS, Windows, ARM, RISC-V

COLOR_GREEN='\033[0;32m'
COLOR_BLUE='\033[0;34m'
COLOR_RED='\033[0;31m'
COLOR_YELLOW='\033[1;33m'
NC='\033[0m'

VERSION=$(sed -n 's/^version = "\([^"]*\)".*/\1/p' Cargo.toml | head -1)
[ -z "$VERSION" ] && VERSION=$(git describe --tags --always --dirty 2>/dev/null || echo "dev")
case "$VERSION" in v*) ;; *) VERSION="v$VERSION" ;; esac
BUILD_DIR="target/dist"

log_info() {
    echo -e "${COLOR_BLUE}[INFO]${NC} $1"
}

log_success() {
    echo -e "${COLOR_GREEN}[SUCCESS]${NC} $1"
}

log_warn() {
    echo -e "${COLOR_YELLOW}[WARN]${NC} $1"
}

log_error() {
    echo -e "${COLOR_RED}[ERROR]${NC} $1"
}

# Check if Rust is installed
check_rust() {
    if ! command -v cargo &> /dev/null; then
        log_error "Rust/Cargo not found. Please install from https://rustup.rs/"
        exit 1
    fi
}

# Install cross-compilation targets
install_targets() {
    log_info "Installing cross-compilation targets..."
    
    # Linux targets
    rustup target add x86_64-unknown-linux-gnu 2>/dev/null || true
    rustup target add aarch64-unknown-linux-gnu 2>/dev/null || true
    rustup target add armv7-unknown-linux-gnueabihf 2>/dev/null || true
    rustup target add riscv64gc-unknown-linux-gnu 2>/dev/null || true
    
    # macOS targets
    rustup target add x86_64-apple-darwin 2>/dev/null || true
    rustup target add aarch64-apple-darwin 2>/dev/null || true
    
    # Windows targets
    rustup target add x86_64-pc-windows-msvc 2>/dev/null || true
    rustup target add aarch64-pc-windows-msvc 2>/dev/null || true
    
    log_success "Targets installed"
}

# Build for a specific target
build_target() {
    local target=$1
    local output_dir="$BUILD_DIR/$target"
    
    log_info "Building for $target..."
    
    mkdir -p "$output_dir"
    
    # Build binaries
    cargo build --release --target "$target" --bin onrouter
    cargo build --release --target "$target" --bin orr-gencert
    
    # Copy binaries to output directory
    if [[ "$target" == *"-windows-"* ]]; then
        cp "target/$target/release/onrouter.exe" "$output_dir/" 2>/dev/null || true
        cp "target/$target/release/orr-gencert.exe" "$output_dir/" 2>/dev/null || true
    else
        cp "target/$target/release/onrouter" "$output_dir/" 2>/dev/null || true
        cp "target/$target/release/orr-gencert" "$output_dir/" 2>/dev/null || true
    fi
    
    log_success "Built for $target"
}

# Create archive for distribution
create_archive() {
    local target=$1
    local output_dir="$BUILD_DIR/$target"
    local archive_name="onrouter-${VERSION}-${target}"
    
    log_info "Creating archive for $target..."
    
    mkdir -p "$BUILD_DIR/archives"
    
    if [[ "$target" == *"-windows-"* ]]; then
        # Windows: ZIP format
        if command -v zip &> /dev/null; then
            cd "$output_dir"
            zip "../../archives/${archive_name}.zip" onrouter.exe orr-gencert.exe 2>/dev/null || \
            zip "../../archives/${archive_name}.zip" *.exe
            cd - > /dev/null
        else
            log_warn "zip not available, skipping Windows archive"
        fi
    else
        # Unix: tar.gz format
        tar czf "$BUILD_DIR/archives/${archive_name}.tar.gz" -C "$output_dir" .
    fi
    
    log_success "Archive created: $BUILD_DIR/archives/${archive_name}.*"
}

# Generate checksums
generate_checksums() {
    log_info "Generating SHA256 checksums..."
    
    cd "$BUILD_DIR/archives"
    sha256sum * > SHA256SUMS.txt 2>/dev/null || shasum -a 256 * > SHA256SUMS.txt
    cd - > /dev/null
    
    log_success "Checksums saved to $BUILD_DIR/archives/SHA256SUMS.txt"
}

# Clean build artifacts
clean() {
    log_info "Cleaning build artifacts..."
    rm -rf "$BUILD_DIR"
    cargo clean
    log_success "Cleaned"
}

# Show build matrix
show_matrix() {
    echo ""
    echo "=== ONRouter Build Matrix ==="
    echo ""
    echo "Operating Systems:"
    echo "  ✓ Linux (x86_64, aarch64, armv7, riscv64)"
    echo "  ✓ macOS (x86_64, aarch64/M1/M2)"
    echo "  ✓ Windows (x86_64, aarch64)"
    echo ""
    echo "Architectures:"
    echo "  • x86_64 (Intel/AMD 64-bit)"
    echo "  • aarch64 (ARM 64-bit, Apple Silicon)"
    echo "  • armv7 (ARM 32-bit, Raspberry Pi)"
    echo "  • riscv64 (RISC-V 64-bit)"
    echo ""
    echo "Output Directory: $BUILD_DIR/archives/"
    echo ""
}

# Main build function
build_all() {
    check_rust
    
    log_info "Starting cross-platform build v$VERSION..."
    echo ""
    
    show_matrix
    
    # Detect current platform
    local current_platform=$(uname -s 2>/dev/null || echo "Windows")
    log_info "Building on: $current_platform"
    echo ""
    
    # Build for current platform only (cross-compilation requires additional setup)
    case "$current_platform" in
        Linux)
            build_target "x86_64-unknown-linux-gnu"
            create_archive "x86_64-unknown-linux-gnu"
            ;;
        Darwin)
            # Detect Intel vs Apple Silicon
            if [[ $(uname -m) == "arm64" ]]; then
                build_target "aarch64-apple-darwin"
                create_archive "aarch64-apple-darwin"
            else
                build_target "x86_64-apple-darwin"
                create_archive "x86_64-apple-darwin"
            fi
            ;;
        MINGW*|MSYS*|CYGWIN*)
            build_target "x86_64-pc-windows-msvc"
            create_archive "x86_64-pc-windows-msvc"
            ;;
        *)
            log_warn "Unknown platform: $current_platform, attempting x86_64 build"
            build_target "x86_64-unknown-linux-gnu"
            create_archive "x86_64-unknown-linux-gnu"
            ;;
    esac
    
    generate_checksums
    
    echo ""
    log_success "Build completed successfully!"
    log_info "Archives available in: $BUILD_DIR/archives/"
    echo ""
}

# Parse arguments
case "${1:-build}" in
    build)
        build_all
        ;;
    clean)
        clean
        ;;
    matrix)
        show_matrix
        ;;
    help|-h|--help)
        echo "Usage: $0 [command]"
        echo ""
        echo "Commands:"
        echo "  build    Build for current platform (default)"
        echo "  clean    Clean build artifacts"
        echo "  matrix   Show supported platforms"
        echo "  help     Show this help"
        echo ""
        echo "For full cross-compilation, use GitHub Actions or Docker."
        ;;
    *)
        log_error "Unknown command: $1"
        exit 1
        ;;
esac
