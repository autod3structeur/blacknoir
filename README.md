# blacknoir

A small, self-hostable end-to-end encrypted messenger. Keys are generated in the
browser and never leave it. The relay server stores and forwards opaque ciphertext
envelopes only.

Built for the people who need it most: journalists and sources, organizers,
caseworkers, clinics, and anyone who should not have to trust a chat provider with
the contents of their conversations.

```
  Browser A                      Relay (Node)                     Browser B
  ---------                      -----------                     ---------
  Ed25519 identity               no private keys                 Ed25519 identity
  X25519 keys                    no plaintext                    X25519 keys
  X3DH handshake          <--- ciphertext envelopes --->          X3DH handshake
  Double Ratchet                 offline queue                   Double Ratchet
  AES-256-GCM                    acknowledgements                AES-256-GCM
```

## What it does

- **First message**: an X3DH handshake against the recipient's published prekey
  bundle establishes a shared secret. The sender's identity key is authenticated by
  the recipient's signed prekey.
- **Every message after**: the Double Ratchet derives a fresh AES-256-GCM key for
  each message. A new Diffie-Hellman ratchet step happens on every round trip, so a
  compromised key does not decrypt earlier or later messages.
- **On the wire**: the relay only sees `from`, `to`, a timestamp, and a base64
  payload. It cannot read message contents, ratchet headers, or the handshake.

## Cryptographic details

| Purpose | Primitive |
| --- | --- |
| Identity signing / auth | Ed25519 |
| Identity and ratchet keys | X25519 |
| Handshake | X3DH (4-DH variant, one-time prekey optional) |
| Root/chain KDF | HKDF-SHA256 |
| Chain step | HMAC-SHA256 |
| Message encryption | AES-256-GCM (12-byte nonce, 128-bit tag) |
| Message key derivation | HKDF-SHA256 to 32-byte key + 12-byte nonce |

Additional authenticated data (AAD) binds the X3DH transcript and the ratchet header
(`dh`, `pn`, `n`) to every ciphertext, so tampering with either fails authentication.

The protocol is implemented in `src/crypto/` with no crypto dependencies beyond
`@noble/curves` for the curves. AES-GCM, HKDF, and HMAC use WebCrypto, which is the
same API in browsers and Node.

## Quick start

```bash
npm install
npm run dev
```

Open <http://localhost:5173>, create an identity, then open a second browser
profile (or incognito window) and create another. Pick each other and chat.

Production:

```bash
npm run build
npm start          # serves dist/ and the relay on :8787
```

Set `PORT` to change the port. The relay persists users and queued messages to
`data/store.json`; mount that directory if you deploy in a container.

## Usage

1. Choose a username. The client generates an Ed25519 key, an X25519 key, a signed
   prekey, and 20 one-time prekeys locally.
2. The username and **public** prekeys are registered with the relay. Private keys
   stay in this browser's local storage.
3. Select a person, send a message. The first message performs X3DH; later messages
   are pure Double Ratchet traffic.
4. Messages are acknowledged and deleted from the relay after decryption. Chat
   history lives only on the device.

## Project layout

```
src/crypto/    X3DH, Double Ratchet, AEAD, key generation, serialization
src/server/    Express API + WebSocket relay, JSON persistence
src/client/    Vanilla TypeScript single-page client (Vite)
tests/         Vitest suite for the protocol
index.html     Client entry
```

## Tests

```bash
npm test
npm run typecheck
npm run build
```

The suite covers X3DH agreement, forged prekey rejection, bidirectional ratcheting,
out-of-order delivery, skipped keys across a DH ratchet, tampered ciphertext and
headers, and session serialization.

## Security model

**Protected against**

- A malicious or compromised relay reading message contents.
- Passive observers of stored data (everything on the server is ciphertext).
- Forgery of a contact's signed prekey.
- Ciphertext or header tampering (AEAD).
- Message-key reuse (each message has a unique key).
- Retroactive decryption after a ratchet step (forward secrecy).
- Replay of an already-processed message (fails authentication and is dropped).

**Not protected against**

- A compromised device. Private keys and local history live in browser storage.
- Metadata: the relay sees usernames, who messages whom, timestamps, and message
  sizes. There is no padding, sealed sender, or traffic-analysis resistance.
- Multi-device use. One identity equals one browser profile; there is no device
  linking or key transparency.
- Simultaneous first messages. If both people message each other before any reply,
  two sessions can be created. This is a known limitation of this MVP.
- Denial of service. There is no rate limiting, spam control, or registration
  gating. Run it for a trusted group or add limits before exposing it widely.
- Side channels in the JavaScript runtime. This is a portable implementation, not a
  constant-time native one.

This code has not been audited. Do not rely on it for life-critical situations
without an independent review.

## Hardening checklist for a public deployment

- Terminate TLS and forward only HTTPS/WSS.
- Back up and restrict access to `data/store.json`.
- Add rate limiting and registration controls.
- Encrypt local storage with a passphrase-derived key (Argon2id).
- Delete used one-time prekeys and rotate the signed prekey.
- Add message padding to reduce size leakage.
- Add multi-device session management.
- Get an external security review.

## License

MIT
