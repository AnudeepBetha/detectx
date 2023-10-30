#!/bin/bash

pip install -r requirements.txt

# Set the desired location of the symlink
SYMLINK_PATH="/usr/local/bin/detectx"

# Create the symlink
ln -s "$(pwd)/detectx.py" "$SYMLINK_PATH"