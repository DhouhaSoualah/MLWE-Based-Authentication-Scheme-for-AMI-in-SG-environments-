# MLWE-Based Authentication Scheme for AMI in Smart Grid Environments

[![Language](https://img.shields.io/badge/C-Implementation-blue.svg)](./c-implementation/)
[![Language](https://img.shields.io/badge/Python-Benchmarking-green.svg)](./python-implementation/)
[![License](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)

## Overview

This repository contains **two complete implementations** of a post-quantum authentication protocol for **Advanced Metering Infrastructure (AMI)** in **Smart Grid (SG)** environments. The scheme is built upon the **Module Learning With Errors (MLWE)** problem, ensuring security against quantum computer attacks.

The protocol enables secure mutual authentication between Smart Meters and the Control Center, with both high-performance and research-friendly implementations.

##  Implementations

| Implementation | Location | Best For | Status |
|----------------|----------|----------|--------|
| **C Implementation** | [`./c-implementation/`](./c-implementation/) | Production, embedded devices | ✅ Complete |
| **Python Implementation** | [`./python-implementation/`](./python-implementation/) | Research, benchmarking, prototyping | 🚧 In Progress |

##  Quick Start

### C Implementation (High Performance)
```bash
cd c-implementation
make
./mlwe
