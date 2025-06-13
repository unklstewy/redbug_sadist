#!/bin/bash
# archive_redbug_sadist.sh
# Script to automate archiving old files in the redbug_sadist project
# Created: June 13, 2025

set -e  # Exit on error

PROJECT_ROOT="/home/sannis/REDBUG/redbug_sadist"
ARCHIVE_DIR="${PROJECT_ROOT}/archive"
ARCHIVE_DATE=$(date +"%Y-%m-%d")

echo "Starting archive process for redbug_sadist..."
echo "Project root: ${PROJECT_ROOT}"
echo "Archive directory: ${ARCHIVE_DIR}"

# Function to create archive directory and add a README
create_archive_structure() {
    echo "Creating archive directory structure..."
    mkdir -p "${ARCHIVE_DIR}"
    mkdir -p "${ARCHIVE_DIR}/pkg/protocol/baofeng/dm32uv/read"
    mkdir -p "${ARCHIVE_DIR}/pkg/protocol/baofeng/dm32uv/write"
    mkdir -p "${ARCHIVE_DIR}/pkg/protocol/analysis"
    mkdir -p "${ARCHIVE_DIR}/cmd/analyzer/read"
    mkdir -p "${ARCHIVE_DIR}/cmd/analyzer/write"
    
    # Create README in archive directory
    cat > "${ARCHIVE_DIR}/README.md" << EOF
# Archived Files from redbug_sadist

These files were archived on ${ARCHIVE_DATE} during a project restructuring.
They represent older implementations that were replaced but kept for reference.

The archived files maintain the original project structure for easier reference.
EOF

    echo "Archive structure created successfully."
}

# Function to add archive note to a file before moving it
archive_file() {
    local src="$1"
    local dest="$2"
    
    if [ ! -f "$src" ]; then
        echo "Warning: Source file $src does not exist, skipping."
        return
    fi
    
    # Create destination directory if it doesn't exist
    mkdir -p "$(dirname "$dest")"
    
    # Add archive note to the file
    cat > "$dest" << EOF
// ARCHIVED FILE - Original from: $src
// Archived on: ${ARCHIVE_DATE}
// This file was archived during project restructuring and kept for reference.
// The functionality has been migrated to new implementations.

EOF
    
    # Append original file contents
    cat "$src" >> "$dest"
    
    echo "Archived: $src -> $dest"
}

# Create the archive structure
create_archive_structure

# Archive files
echo "Archiving files..."

# Files from /pkg/protocol/baofeng/dm32uv/read/
archive_file "${PROJECT_ROOT}/pkg/protocol/baofeng/dm32uv/read/analyzer.go.bak" "${ARCHIVE_DIR}/pkg/protocol/baofeng/dm32uv/read/analyzer.go.bak"
archive_file "${PROJECT_ROOT}/pkg/protocol/baofeng/dm32uv/read/analyzer_impl.go" "${ARCHIVE_DIR}/pkg/protocol/baofeng/dm32uv/read/analyzer_impl.go"
archive_file "${PROJECT_ROOT}/pkg/protocol/baofeng/dm32uv/read/types.go" "${ARCHIVE_DIR}/pkg/protocol/baofeng/dm32uv/read/types.go"
archive_file "${PROJECT_ROOT}/pkg/protocol/baofeng/dm32uv/read/analyzer_convert.go" "${ARCHIVE_DIR}/pkg/protocol/baofeng/dm32uv/read/analyzer_convert.go"

# Files from /pkg/protocol/baofeng/dm32uv/
archive_file "${PROJECT_ROOT}/pkg/protocol/baofeng/dm32uv/analyzer.go" "${ARCHIVE_DIR}/pkg/protocol/baofeng/dm32uv/analyzer.go"

# Files from /cmd/analyzer/
archive_file "${PROJECT_ROOT}/cmd/analyzer/main.go" "${ARCHIVE_DIR}/cmd/analyzer/main.go"
archive_file "${PROJECT_ROOT}/cmd/analyzer/read/main.go" "${ARCHIVE_DIR}/cmd/analyzer/read/main.go"
archive_file "${PROJECT_ROOT}/cmd/analyzer/write/main.go" "${ARCHIVE_DIR}/cmd/analyzer/write/main.go"

# Files from /pkg/protocol/analysis/
archive_file "${PROJECT_ROOT}/pkg/protocol/analysis/analyzer.go" "${ARCHIVE_DIR}/pkg/protocol/analysis/analyzer.go"

# Add .gitignore to exclude archive from git
if ! grep -q "^/archive/" "${PROJECT_ROOT}/.gitignore" 2>/dev/null; then
    echo "Adding /archive/ to .gitignore..."
    echo -e "\n# Archived files\n/archive/" >> "${PROJECT_ROOT}/.gitignore"
fi

echo "Archive process completed."
echo "Archived files are in: ${ARCHIVE_DIR}"
echo "Remember to update imports in the remaining files to match the new structure."
