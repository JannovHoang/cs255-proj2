# Project 2 – End-to-End Encrypted Messenger

## 1. Description
This project implements the **Double Ratchet Protocol** based on the Signal specification, providing secure end-to-end encrypted messaging.

Each message uses a fresh key, ensuring long-term confidentiality and post-compromise security.

---

## 2. Objectives
- End-to-end encrypted messaging
- Server cannot read plaintext
- Forward secrecy

---

## 3. Threat Model
The attacker can:
- Eavesdrop on the network
- Replay messages
- Temporarily compromise a device

---

## 4. Cryptographic Primitives
- ECDH – key exchange
- HKDF – root/chain key derivation
- HMAC-SHA256 – ratcheting
- AES-256-GCM – message encryption

---

## 5. Sending Flow
- Double Ratchet derives messageKey
- AES-GCM encrypts message
- Send {header, ciphertext}

---

## 6. Receiving Flow
- Ratchet state synchronization
- Derive messageKey
- AES-GCM decrypt & verify

---

## 7. Security Properties
- Forward secrecy
- Break-in recovery
- Replay and out-of-order handling

---

## 8. How to Run
```bash
npm install
npm test