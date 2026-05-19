# MLWE-Based Authentication Scheme for AMI in SG Environments

[![Language](https://img.shields.io/badge/language-C-blue.svg)](https://en.wikipedia.org/wiki/C_(programming_language))
[![License](https://img.shields.io/badge/license-MIT-green.svg)](LICENSE)
[![Made with](https://img.shields.io/badge/Made%20with-Kyber-ff69b4.svg)](https://pq-crystals.org/kyber/)

## Overview
This repository contains a **C implementation** of an authentication protocol for **Advanced Metering Infrastructure (AMI)** within **Smart Grid (SG)** environments. The scheme is built upon the **Module Learning With Errors (MLWE)** problem, ensuring security against quantum computer attacks.

The protocol enables secure mutual authentication between:
- **Smart Meters**
- **Control Center**

## Features
- **Post-Quantum Security**: Based on the MLWE problem (Kyber512 core).
- **Mutual Authentication**: Verifies identities of both meters and the control center.
- **Key Establishment**: Generates session keys for encrypted communication.
- **Lightweight Design**: Suitable for resource-constrained AMI devices.
- **Standard Cryptographic Primitives**: Uses SHA-256 for hashing.

## Project Structure
