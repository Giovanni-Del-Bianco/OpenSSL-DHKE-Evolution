#!/bin/bash

# ==============================================================================
# Script: run_test_interleaved.sh
# Project: OpenSSL DHKE Lab
#
# Purpose:
#   This script automates the setup for the interleaved test between two parties
#   (Alice and Bob) using Diffie-Hellman key exchange and encryption.
#
#   It performs:
#     1. Cleanup of previous temporary files
#     2. Compilation of the final implementation (Step 4)
#     3. Displays clear instructions to run the protocol manually
#
# Requirements:
#   - GCC compiler
#   - OpenSSL development libraries (libssl-dev)
#
# Notes:
#   The protocol requires two separate terminals to simulate two entities.
# ==============================================================================

# -----------------------------
# Color definitions for output
# -----------------------------
GREEN='\033[0;32m'   # Informational / success messages
RED='\033[0;31m'     # Error messages
BOLD='\033[1m'       # Bold text
NC='\033[0m'         # Reset color

# -----------------------------
# Step 1: Cleanup environment
# -----------------------------
echo -e "${GREEN}[*] Cleaning up temporary files...${NC}"

# Remove previously generated files:
# *_pub.pem     -> public keys
# *_cipher.enc  -> encrypted messages
# *_plain.txt   -> decrypted plaintexts
rm -f *_pub.pem *_cipher.enc *_plain.txt

# -----------------------------
# Step 2: Compile the program
# -----------------------------
echo -e "${GREEN}[*] Compiling the project...${NC}"

# Compile the main DH automation program
# -lcrypto links OpenSSL cryptographic library
gcc src/4_full_automation/dh_full_api.c -o bin/dh_full -lcrypto

# Check compilation result
if [ $? -ne 0 ]; then
    echo -e "${RED}[-] Compilation failed.${NC}"
    echo "    Make sure OpenSSL development libraries are installed:"
    echo "    sudo apt install libssl-dev"
    exit 1
fi

echo -e "${GREEN}[+] Compilation completed successfully.${NC}"

# -----------------------------
# Step 3: Display instructions
# -----------------------------
echo -e "\n${BOLD}=== INTERLEAVED TEST INSTRUCTIONS ===${NC}"

echo "This protocol simulates a secure communication between two parties"
echo "using Diffie-Hellman key exchange."

echo ""
echo "You MUST open two separate terminals to simulate Alice and Bob."

echo ""
echo -e "${GREEN}TERMINAL 1 (Alice):${NC}"
echo "  ./bin/dh_full Alice Bob"

echo ""
echo -e "${GREEN}TERMINAL 2 (Bob):${NC}"
echo "  ./bin/dh_full Bob Alice"

echo ""
echo "----------------------------------------------------------------"
echo "Follow the on-screen instructions in BOTH terminals to:"
echo "  1. Exchange public keys (.pem files)"
echo "  2. Exchange encrypted messages (.enc files)"
echo "----------------------------------------------------------------"

