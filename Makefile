# ==============================================================================
# Makefile for OpenSSL DHKE Lab
# Author: Giovanni Del Bianco
# ==============================================================================

CC = gcc
CFLAGS = -Wall
LIBS = -lcrypto
BIN_DIR = bin


all: setup step1 step2 step3 step4

setup:
	@mkdir -p $(BIN_DIR)

step1:
	$(CC) $(CFLAGS) src/1_manual_dh/dh_manual.c -o $(BIN_DIR)/dh_manual $(LIBS)

step2:
	$(CC) $(CFLAGS) src/2_elliptic_curves/ecdh_lab.c -o $(BIN_DIR)/ecdh_lab $(LIBS)

step3:
	$(CC) $(CFLAGS) src/3_api_keygen/dh_api_keygen.c -o $(BIN_DIR)/dh_api_keygen $(LIBS)

step4:
	$(CC) $(CFLAGS) src/4_full_automation/dh_full_api.c -o $(BIN_DIR)/dh_full $(LIBS)

clean:
	rm -rf $(BIN_DIR) *.pem *.enc samples/*.enc
	@echo "Pulizia completata."

.PHONY: all setup step1 step2 step3 step4 clean