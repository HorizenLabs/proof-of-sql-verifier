#!/bin/bash

# Check if at least two arguments are provided
if [ "$#" -lt 2 ]; then
  echo "Usage: $0 <header-file> <file-pattern>"
  exit 1
fi

# Read arguments
HEADER_FILE="$1"
FILE_PATTERN="$2"

# Read the license header from the specified file
if [ ! -f "$HEADER_FILE" ]; then
  echo "Header file not found: $HEADER_FILE"
  exit 1
fi

LICENSE_HEADER=$(cat "$HEADER_FILE")

# Loop through all Rust files matching the pattern
shopt -s globstar
for file in $FILE_PATTERN; do
  if [[ -f "$file" && "$file" == *.rs ]]; then
    if ! grep -q "Copyright 2024, Horizen Labs, Inc." "$file"; then
      echo "Adding license header to $file"
      echo -e "$LICENSE_HEADER\n$(cat $file)" > "$file"
    fi
  fi
done