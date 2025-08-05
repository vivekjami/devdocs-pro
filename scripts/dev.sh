#!/bin/bash
export RUST_LOG=debug
export DEVDOCS_API_KEY=dev_key_123
cargo watch -x "build" -x "test"
