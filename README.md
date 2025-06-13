# REDBUG_SADIST - Serial Protocol Analysis Tool

A tool for analyzing and documenting radio communication protocols by capturing and interpreting 
serial communications between programming software and radio devices.

## Supported Vendors and Models

### Baofeng
- DM-32UV (DMR)
- UV-5R (Analog)
- BF-888S (Analog)

### TYT
- MD-380 (DMR)

## Architecture

The code is organized by:
- Vendor
- Radio Model
- Analysis Type (read/write)

## Usage

```
redbug_sadist analyze baofeng dm32uv read <capture_file>
redbug_sadist analyze baofeng dm32uv write <capture_file>
```
