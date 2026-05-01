#!/bin/bash

# ==============================================================================
# Script: gen_dh_params.sh
# Project: OpenSSL DHKE Lab
# Purpose:
#   This script generates secure Diffie-Hellman (DH) parameters (2048-bit).
#   These parameters are typically used in cryptographic protocols to securely
#   exchange keys over an insecure channel.
#
# Notes:
#   - The generation process may take a significant amount of time because
#     it involves finding a "safe prime".
#   - Requires OpenSSL (version 3.x recommended).
# ==============================================================================

# -----------------------------
# Color definitions for output
# -----------------------------
GREEN='\033[0;32m'   # Green color for success/info messages
RED='\033[0;31m'     # Red color for error messages
NC='\033[0m'         # No Color (reset)

# -----------------------------
# Start message
# -----------------------------
echo -e "${GREEN}[*] Starting Diffie-Hellman parameter generation (2048-bit)...${NC}"
echo "[!] Note: This operation may take some time due to safe prime generation."

# -----------------------------
# OpenSSL command explanation:
#
# -genparam:
#   Generates only the parameters (NOT the key pair).
#
# -algorithm DH:
#   Specifies the Diffie-Hellman algorithm.
#
# -pkeyopt dh_paramgen_prime_len:2048:
#   Sets the size (in bits) of the prime number 'p'.
#   2048 bits is considered a secure standard.
#
# -out dhparams.pem:
#   Output file where the generated parameters will be stored.
# -----------------------------
openssl genpkey -genparam \
    -algorithm DH \
    -pkeyopt dh_paramgen_prime_len:2048 \
    -out dhparams.pem

# -----------------------------
# Check the exit status of OpenSSL
# $? contains the exit code of the last executed command:
#   0   -> success
#   !=0 -> error
# -----------------------------
if [ $? -eq 0 ]; then
    echo -e "${GREEN}[+] DH parameters successfully generated in: dhparams.pem${NC}"
else
    echo -e "${RED}[-] Error: Failed to generate DH parameters.${NC}"
    exit 1
fi

