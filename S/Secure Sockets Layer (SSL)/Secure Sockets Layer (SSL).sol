// SPDX-License-Identifier: MIT
pragma solidity ^0.8.25;

/*//////////////////////////////////////////////////////////////
                        LIBRARY: ECDSA RECOVER
//////////////////////////////////////////////////////////////*/
error SSL_InvalidSignature();

library SigLib {
    /// @dev recover signer from "\x19Ethereum Signed Message:\n32"+hash
    function recover(bytes32 hash, bytes calldata sig) internal pure returns (address) {
        if (sig.length != 65) revert SSL_InvalidSignature();
        bytes32 r;
        bytes32 s;
        uint8   v;
        assembly {
            r := calldataload(sig.offset)
            s := calldataload(add(sig.offset, 32))
            v := byte(0, calldataload(add(sig.offset, 64)))
        }
        return ecrecover(
            keccak256(abi.encodePacked("\x19Ethereum Signed Message:\n32", hash)),
            v, r, s
        );
    }
}

/*//////////////////////////////////////////////////////////////
                  1. BASIC HANDSHAKE (VULNERABLE)
//////////////////////////////////////////////////////////////*/
contract BasicSSL {
    /// @notice client derives sessionKey = keccak256(serverEphemeral, clientAddr)
    mapping(address => bytes32) public sessionKey;
    event Handshake(address indexed client, bytes32 sessionKey);

    /// @dev no validation → MITM can send attacker’s ephemeral
    function handshakeBasic(bytes32 serverEphemeral) external {
        bytes32 key = keccak256(abi.encodePacked(serverEphemeral, msg.sender));
        sessionKey[msg.sender] = key;
        emit Handshake(msg.sender, key);
    }
}

/// @dev MITM attacker calls handshakeBasic with their own key
contract Attack_BasicMITM {
    BasicSSL public ssl;
    constructor(BasicSSL _ssl) { ssl = _ssl; }

    function mitmHandshake(bytes32 fakeEphemeral) external {
        // client unknowingly uses fakeEphemeral → session compromised
        ssl.handshakeBasic(fakeEphemeral);
    }
}

/*//////////////////////////////////////////////////////////////
        2. CERTIFICATE‑VERIFIED HANDSHAKE (HARDENED)
//////////////////////////////////////////////////////////////*/
error SSL_InvalidCert();

contract CertSSL {
    using SigLib for bytes32;

    address public immutable CA;  // on‑chain CA public key
    mapping(address => bytes32) public sessionKey;
    event Handshake(address indexed client, bytes32 sessionKey);

    constructor(address _ca) {
        CA = _ca;
    }

    /// @notice serverEphemeral signed off‑chain by CA
    function handshakeCert(bytes32 serverEphemeral, bytes calldata caSig) external {
        // verify CA signature over serverEphemeral
        if (CA != serverEphemeral.recover(caSig)) revert SSL_InvalidCert();

        bytes32 key = keccak256(abi.encodePacked(serverEphemeral, msg.sender));
        sessionKey[msg.sender] = key;
        emit Handshake(msg.sender, key);
    }
}

/// @dev Attacker tries forging CA signature → always reverts
contract Attack_CertMITM {
    CertSSL public ssl;
    constructor(CertSSL _ssl) { ssl = _ssl; }

    function fakeHandshake(bytes32 fakeEph, bytes calldata fakeSig) external {
        // revert SSL_InvalidCert()
        ssl.handshakeCert(fakeEph, fakeSig);
    }
}

/*//////////////////////////////////////////////////////////////
      3. MUTUAL‑AUTHENTICATION HANDSHAKE (HARDENED)
//////////////////////////////////////////////////////////////*/
error SSL_InvalidClient();

contract MutualSSL {
    using SigLib for bytes32;

    address public immutable CA;
    mapping(address => bytes32) public sessionKey;
    event Handshake(address indexed client, bytes32 sessionKey);

    constructor(address _ca) {
        CA = _ca;
    }

    /// @notice both server and client present ECDSA signatures
    function handshakeMutual(
        bytes32 serverEphemeral,
        bytes calldata caSig,
        bytes32 clientEphemeral,
        bytes calldata clientSig
    ) external {
        // 1) verify server by CA
        if (CA != serverEphemeral.recover(caSig)) revert SSL_InvalidCert();

        // 2) verify client by their EOA
        if (msg.sender != clientEphemeral.recover(clientSig)) revert SSL_InvalidClient();

        // derive shared session key
        bytes32 key = keccak256(abi.encodePacked(serverEphemeral, clientEphemeral));
        sessionKey[msg.sender] = key;
        emit Handshake(msg.sender, key);
    }
}

/// @dev Attacker supplies bad clientSig → always reverts
contract Attack_MutualFail {
    MutualSSL public ssl;
    constructor(MutualSSL _ssl) { ssl = _ssl; }

    function attemptMutual(
        bytes32 servEph,
        bytes calldata servSig,
        bytes32 fakeCliEph,
        bytes calldata fakeCliSig
    ) external {
        // revert SSL_InvalidClient()
        ssl.handshakeMutual(servEph, servSig, fakeCliEph, fakeCliSig);
    }
}
