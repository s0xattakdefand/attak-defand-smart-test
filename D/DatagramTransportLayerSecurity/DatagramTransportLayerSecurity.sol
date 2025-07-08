// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

/*
 * DATAGRAM TRANSPORT LAYER SECURITY (DTLS) DEMO
 * — Provides a vulnerable channel with no security vs. a
 *   simulated DTLS-like handshake and record layer with
 *   authentication, sequencing, and anti-replay protection.
 */

/*----------------------------------------------------------------------------
   SECTION 1 — VulnerableDatagramChannel
   • Anyone can send arbitrary "datagrams" to any recipient.
   • No confidentiality, integrity, or replay protection.
----------------------------------------------------------------------------*/
contract VulnerableDatagramChannel {
    event DatagramSent(address indexed from, address indexed to, bytes payload);

    /// Transmit a datagram with no security guarantees.
    function sendDatagram(address to, bytes calldata payload) external {
        emit DatagramSent(msg.sender, to, payload);
    }
}

/*----------------------------------------------------------------------------
   SECTION 2 — MiniECDSA (for signatures)
----------------------------------------------------------------------------*/
library MiniECDSA {
    function toEthSignedMessageHash(bytes32 h) internal pure returns (bytes32) {
        return keccak256(abi.encodePacked("\x19Ethereum Signed Message:\n32", h));
    }
    function recover(bytes32 h, bytes calldata sig) internal pure returns (address) {
        require(sig.length == 65, "ECDSA: bad sig length");
        bytes32 r; bytes32 s; uint8 v;
        assembly {
            r := calldataload(sig.offset)
            s := calldataload(add(sig.offset,32))
            v := byte(0, calldataload(add(sig.offset,64)))
        }
        return ecrecover(toEthSignedMessageHash(h), v, r, s);
    }
}

/*----------------------------------------------------------------------------
   SECTION 3 — DTLSChannel (✅ simulated DTLS)
   • Handshake: client and server exchange ephemeral nonces, each signed
     by their static identity keys for authentication.
   • Record layer: messages carry sequence numbers and signatures to ensure
     integrity and prevent replay.
----------------------------------------------------------------------------*/
contract DTLSChannel {
    using MiniECDSA for bytes32;

    struct Handshake {
        bytes32 clientNonce;
        bytes32 serverNonce;
        bool    complete;
    }

    // handshake state per (client → server)
    mapping(address => mapping(address => Handshake)) public handshakes;
    // last sequence number seen per (sender → recipient)
    mapping(address => mapping(address => uint256)) public lastSeq;

    event HandshakeInitiated(address indexed client, address indexed server, bytes32 clientNonce);
    event HandshakeResponded(address indexed client, address indexed server, bytes32 serverNonce);
    event DTLSMessage(
        address indexed from,
        address indexed to,
        uint256 seq,
        bytes32 payloadHash
    );

    /// Client starts handshake by sending a nonce signed with its static key.
    function initiateHandshake(
        address server,
        bytes32 clientNonce,
        bytes calldata clientSig
    ) external {
        bytes32 h = keccak256(abi.encodePacked(address(this), msg.sender, server, clientNonce));
        require(h.recover(clientSig) == msg.sender, "Invalid client signature");

        Handshake storage s = handshakes[msg.sender][server];
        require(!s.complete, "Handshake already done");
        s.clientNonce = clientNonce;
        emit HandshakeInitiated(msg.sender, server, clientNonce);
    }

    /// Server responds with its own nonce, also signed.
    function respondHandshake(
        address client,
        bytes32 serverNonce,
        bytes calldata serverSig
    ) external {
        Handshake storage s = handshakes[client][msg.sender];
        require(!s.complete, "Handshake already done");
        require(s.clientNonce != bytes32(0), "No initiation");

        bytes32 h = keccak256(abi.encodePacked(address(this), client, msg.sender, serverNonce));
        require(h.recover(serverSig) == msg.sender, "Invalid server signature");

        s.serverNonce = serverNonce;
        s.complete    = true;
        emit HandshakeResponded(client, msg.sender, serverNonce);
    }

    /// After handshake, sender transmits messages with seq and signature.
    /// Replay is prevented by enforcing seq > lastSeq.
    function sendDTLSMessage(
        address to,
        uint256 seq,
        bytes32 payloadHash,
        bytes calldata msgSig
    ) external {
        Handshake storage s = handshakes[msg.sender][to];
        require(s.complete, "Handshake not complete");
        require(seq > lastSeq[msg.sender][to], "Replay or out-of-order");

        bytes32 h = keccak256(
            abi.encodePacked(address(this), msg.sender, to, seq, payloadHash, s.clientNonce, s.serverNonce)
        );
        require(h.recover(msgSig) == msg.sender, "Invalid message signature");

        lastSeq[msg.sender][to] = seq;
        emit DTLSMessage(msg.sender, to, seq, payloadHash);
    }
}
