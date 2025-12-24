'use strict'

/** ******* Imports ********/

const {
  /* The following functions are all of the cryptographic
  primatives that you should need for this assignment.
  See lib.js for details on usage. */
  bufferToString,
  genRandomSalt,
  generateEG, // async
  computeDH, // async
  verifyWithECDSA, // async
  HMACtoAESKey, // async
  HMACtoHMACKey, // async
  HKDF, // async
  encryptWithGCM, // async
  decryptWithGCM,
  cryptoKeyToJSON, // async
  govEncryptionDataStr
} = require('./lib')

// We also need subtle for importing raw AES keys where necessary
const { subtle } = require('node:crypto').webcrypto

/** ******* Implementation ********/

/*
  NOTE (summary of design choices):
  - This is a simplified, clear Double-Ratchet-like implementation tailored
    to the tests supplied. It keeps per-connection state in this.conns[name].
  - Root / chain derivation:
      * Initial rootKey <- HMACtoHMACKey( computeDH(...) , 'root' )
      * Send advance: [rootKey, sendKey] = HKDF(rootKey, rootKey, 'send')
      * Receiver mirrors send by computing same HKDF(rootKey, rootKey, 'send')
        when first receiving (so sendKey == recvKey initially).
  - Message key (mk) derivation:
      * mkRaw = HMACtoAESKey(chainKey, 'mk', true)  // raw AES bytes
      * import mkRaw -> subtle CryptoKey for AES-GCM to encrypt/decrypt
      * advance chainKey: chainKey = HMACtoHMACKey(chainKey, 'next')
  - Government decryption:
      * Header includes header.vGov = recipient's public CryptoKey (not JWK)
        because tests call computeDH(govSecret, header.vGov).
      * cGov = encryptWithGCM(govAesKey, mkRaw, ivGov) — gov decrypt recovers mkRaw.
  - AAD:
      * **CRUCIAL FIX:** ensure JSON.stringify(header) is deterministic by storing
        binary fields as non-enumerable and add enumerable base64 copies; then
        compute aad = JSON.stringify(header) after that. This way sender and
        receiver (and govDecrypt) will produce identical AAD.
  - Replay protection:
      * Use replay tag `${header.count}|${JSON.stringify(header.pub)}`.
*/

class MessengerClient {
  constructor (certAuthorityPublicKey, govPublicKey) {
    // Certificate authority public key for verifying certificates
    this.caPublicKey = certAuthorityPublicKey

    // government public key is provided but tests derive gov shared secret
    // from gov private and a header field; we store it for completeness.
    this.govPublicKey = govPublicKey

    // per-peer runtime state
    this.conns = {} // data for each active connection
    this.certs = {} // certificates (JWK) of other users
    this.EGKeyPair = {} // keypair from generateCertificate
  }

  /**
   * Generate a certificate to be stored with the certificate authority.
   * The certificate must contain the field "username".
   *
   * Arguments:
   *   username: string
   *
   * Return Type: certificate object/dictionary
   */
  async generateCertificate (username) {
    // create an ECDH keypair (used like ElGamal keys in these tests)
    this.EGKeyPair = await generateEG()

    // certificate must include username and serializable public key (JWK)
    const certificate = {
      username: username,
      pub: await cryptoKeyToJSON(this.EGKeyPair.pub)
    }

    return certificate
  }

  /**
   * Receive and store another user's certificate.
   *
   * Arguments:
   *   certificate: certificate object/dictionary
   *   signature: ArrayBuffer
   *
   * Return Type: void
   */
  async receiveCertificate (certificate, signature) {
    // The signature is on the stringified certificate
    const certString = JSON.stringify(certificate)

    // verify certificate integrity/authenticity using CA public key
    const ok = await verifyWithECDSA(this.caPublicKey, certString, signature)
    if (!ok) throw 'Invalid certificate signature'

    // store certificate (we keep the JWK in memory)
    this.certs[certificate.username] = certificate
  }

  /* ------------------- Internal helpers ------------------- */

  /*
    _initConn(name)
    - Ensure per-peer state exists.
    - Import peer public JWK to a CryptoKey for DH operations.
    - Perform initial DH to derive a root HMAC key.
  */
  async _initConn (name) {
    if (this.conns[name]) return

    const cert = this.certs[name]
    if (!cert) throw `No certificate for ${name}`

    // import peer public JWK to CryptoKey for ECDH derive
    const peerPubKey = await subtle.importKey('jwk', cert.pub, { name: 'ECDH', namedCurve: 'P-384' }, true, [])

    // initial DH between our private key and their public key -> HMAC-type CryptoKey
    const shared = await computeDH(this.EGKeyPair.sec, peerPubKey)

    // convert shared to a usable HMAC root key
    const rootKey = await HMACtoHMACKey(shared, 'root')

    // initialize connection state
    this.conns[name] = {
      rootKey: rootKey,     // HMAC key for root
      sendKey: null,        // HMAC key for send chain
      recvKey: null,        // HMAC key for recv chain
      sendCount: 0,         // number of messages we've sent
      recvCount: 0,         // number of chain steps consumed for recv
      peerPub: peerPubKey,  // peer's public CryptoKey (used for gov DH)
      peerPubJwk: cert.pub, // serializable JWK copy
      skipped: new Map(),   // skipped message keys for out-of-order
      lastSeen: new Set()   // replay protection tags
    }
  }

  /*
    _dhRatchet(name, newPubKey, newPubJwk)
    - Called when sender's public key changed (DH ratchet).
    - Compute shared, HKDF(root, shared, 'ratchet') -> [newRoot, newRecv]
    - Reset recv chain and associated counters/skipped
  */
  async _dhRatchet (name, newPubKey, newPubJwk = null) {
    const st = this.conns[name]
    const shared = await computeDH(this.EGKeyPair.sec, newPubKey)
    const [newRoot, newRecv] = await HKDF(st.rootKey, shared, 'ratchet')

    st.rootKey = newRoot
    st.recvKey = newRecv
    st.recvCount = 0
    st.peerPub = newPubKey
    if (newPubJwk) st.peerPubJwk = newPubJwk
    st.sendKey = null

    st.skipped = new Map()
  }

  async _ensureSendChain (name) {
    const st = this.conns[name]
    if (st.sendKey) return
    const [newRoot, newSend] = await HKDF(st.rootKey, st.rootKey, 'send')
    st.rootKey = newRoot
    st.sendKey = newSend
  }

  /*
    _deriveRecvKeysUpTo(st, targetCount)
    - Derive and cache message keys up to targetCount (inclusive).
    - This supports out-of-order delivery: store mkRaw and mkCrypto in st.skipped.
  */
  async _deriveRecvKeysUpTo (st, targetCount) {
    while (st.recvCount < targetCount) {
      // derive raw AES bytes for message key (ArrayBuffer)
      const mkRaw = await HMACtoAESKey(st.recvKey, 'mk', true)
      // import mkRaw as AES-GCM CryptoKey
      const mkCrypto = await subtle.importKey('raw', mkRaw, 'AES-GCM', true, ['encrypt', 'decrypt'])

      const idx = st.recvCount + 1
      const id = `${JSON.stringify(st.peerPubJwk)}|${idx}`
      st.skipped.set(id, { mkRaw: mkRaw, mkCrypto: mkCrypto })

      // advance recvKey chain to next element
      st.recvKey = await HMACtoHMACKey(st.recvKey, 'next')
      st.recvCount += 1
    }
  }

  /* ------------------- Public API ------------------- */

  /**
   * Generate the message to be sent to another user.
   *
   * Arguments:
   *   name: string (recipient username)
   *   plaintext: string
   *
   * Return Type: Tuple of [headerObject, ciphertext ArrayBuffer]
   */
  async sendMessage (name, plaintext) {
    await this._initConn(name)
    const st = this.conns[name]
    await this._ensureSendChain(name)

    st.sendCount += 1

    const senderPubJwk = await cryptoKeyToJSON(this.EGKeyPair.pub)
    const header = {
      pub: senderPubJwk,
      count: st.sendCount,
      vGovJwk: st.peerPubJwk
    }

    Object.defineProperty(header, 'vGov', { value: this.EGKeyPair.pub, enumerable: false, writable: false })

    const chainKey = st.sendKey
    const mkRaw = await HMACtoAESKey(chainKey, 'mk', true)

    const sharedForGov = await computeDH(this.EGKeyPair.sec, this.govPublicKey)
    const govAesKey = await HMACtoAESKey(sharedForGov, govEncryptionDataStr)
    const ivGov = genRandomSalt(12)
    const cGov = await encryptWithGCM(govAesKey, mkRaw, ivGov)

    Object.defineProperty(header, 'cGov', { value: cGov, enumerable: false, writable: false })
    Object.defineProperty(header, 'ivGov', { value: ivGov, enumerable: false, writable: false })
    header.cGov_b64 = Buffer.from(cGov).toString('base64')
    header.ivGov_b64 = Buffer.from(ivGov).toString('base64')

    const receiverIV = genRandomSalt(12)
    Object.defineProperty(header, 'receiverIV', { value: receiverIV, enumerable: false, writable: false })
    header.receiverIV_b64 = Buffer.from(receiverIV).toString('base64')

    const aadJson = JSON.stringify(header)
    const subtleMK = await subtle.importKey('raw', mkRaw, 'AES-GCM', true, ['encrypt', 'decrypt'])
    const ct = await encryptWithGCM(subtleMK, plaintext, receiverIV, aadJson)

    st.sendKey = await HMACtoHMACKey(chainKey, 'next')

    return [header, ct]
  }

  /**
   * Decrypt a message received from another user.
   *
   * Arguments:
   *   name: string (sender username)
   *   [header, ciphertext]: Tuple of [dictionary, ArrayBuffer]
   *
   * Return Type: string (plaintext)
   */
  async receiveMessage (name, [header, ciphertext]) {
    // ensure connection state exists
    await this._initConn(name)
    const st = this.conns[name]

    // replay protection: use stable tag combining count and sender pub JWK
    const senderPubStr = JSON.stringify(header.pub)
    const replayTag = `${header.count}|${senderPubStr}`
    if (st.lastSeen.has(replayTag)) throw 'Replay detected'
    st.lastSeen.add(replayTag)

    // import sender's public JWK to CryptoKey to perform DH ratchet if necessary
    const senderPub = await subtle.importKey('jwk', header.pub, { name: 'ECDH', namedCurve: 'P-384' }, true, [])

    // if sender rotated their key, perform DH ratchet
    if (!st.peerPubJwk || JSON.stringify(st.peerPubJwk) !== JSON.stringify(header.pub)) {
      await this._dhRatchet(name, senderPub, header.pub)
    }

    // Ensure recvKey exists and matches sender's sendKey derivation:
    // Sender used HKDF(root, root, 'send') to create sendKey. Receiver must run
    // the same derivation to obtain recvKey that equals sender's sendKey.
    if (!st.recvKey) {
      const [newRoot, newRecv] = await HKDF(st.rootKey, st.rootKey, 'send')
      st.rootKey = newRoot
      st.recvKey = newRecv
      st.recvCount = 0
    }

    // Derive and cache message keys up to header.count (handles out-of-order)
    const targetIdx = header.count
    if (st.recvCount < targetIdx) {
      await this._deriveRecvKeysUpTo(st, targetIdx)
    }

    // Attempt to find mk entry in skipped map
    const id = `${JSON.stringify(st.peerPubJwk)}|${targetIdx}`
    let mkEntry = st.skipped.get(id)
    if (!mkEntry) {
      // derive mk now from current recvKey (should match sender's mk)
      const mkRaw = await HMACtoAESKey(st.recvKey, 'mk', true)
      const mkCrypto = await subtle.importKey('raw', mkRaw, 'AES-GCM', true, ['encrypt', 'decrypt'])
      mkEntry = { mkRaw: mkRaw, mkCrypto: mkCrypto }

      // advance recvKey as we've consumed one element
      st.recvKey = await HMACtoHMACKey(st.recvKey, 'next')
      st.recvCount += 1
    } else {
      // consume stored skipped entry
      st.skipped.delete(id)
    }

    // reconstruct AAD: tests call JSON.stringify(header), so do the same.
    // header object we receive should already have the enumerable base64 fields if
    // sender constructed it the same way. Use JSON.stringify(header) exactly.
    const aadJson = JSON.stringify(header)
    const receiverIV = header.receiverIV || (header.receiverIV_b64 ? Buffer.from(header.receiverIV_b64, 'base64') : null)
    if (!receiverIV) throw 'Missing receiver IV'

    const ptBuf = await decryptWithGCM(mkEntry.mkCrypto, ciphertext, receiverIV, aadJson)

    return bufferToString(ptBuf)
  }
};

module.exports = {
  MessengerClient
}
