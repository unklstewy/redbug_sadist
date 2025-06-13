# Test Data for Protocol Analysis

This directory contains test data files used for automated testing of the protocol analyzers.

## Directory Structure

- `baofeng/`
  - `dm32uv/`
    - `read/`: Contains read operation test data
    - `write/`: Contains write operation test data
- `tyt/`
  - `md380/`
    - `read/`: Contains read operation test data
    - `write/`: Contains write operation test data

## File Types

- `*.log`: Short trace log files
- `*.log.golden`: Expected parsed output
- `*.bin`: Binary protocol dumps
- `*.json`: Expected analysis results
