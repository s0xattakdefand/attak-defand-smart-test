// SPDX-License-Identifier: MIT
pragma solidity ^0.8.25;

/// @title DigitalSignatureSuite.sol
/// @notice On‑chain analogues of “Digital Signature” patterns:
///   Types: RSA, ECDSA, EdDSA  
///   AttackTypes: SignatureForgery, ReplayAttack, NonceReuse  
///   DefenseTypes: SignatureValidation, NonceValidation, MultiSignature  

enum DigitalSignatureType          { RSA, ECDSA, EdDSA }
enum DigitalSignatureAttackType    { SignatureForgery, ReplayAttack, NonceReuse }
enum DigitalSignatureDefenseType   { SignatureValidation, NonceValidation, MultiSignature }

error DS__InvalidSignature();
error DS__ReplayDetected();
error DS__NotSigner();
error DS__InsufficientSignatures();

///─────────────────────────────────────────────────────────────────────────────
/// 1) VULNERABLE SIGNATURE VERIFIER
///
///    • no checks: always accepts any signature  
///    • Attack: SignatureForgery
///─────────────────────────────────────────────────────────────────────────────
contract DigitalSignatureVuln {
    event Verified(
        address indexed who,
        bytes    message,
        bytes    signature,
        bool     valid,
        DigitalSignatureAttackType attack
    );

    function verify(
        DigitalSignatureType stype,
        bytes calldata message,
        bytes calldata signature
    ) external {
        // ❌ no validation
        emit Verified(msg.sender, message, signature, true, DigitalSignatureAttackType.SignatureForgery);
    }
}

///─────────────────────────────────────────────────────────────────────────────
/// 2) ATTACK STUB
///
///    • forge or replay signatures  
///─────────────────────────────────────────────────────────────────────────────
contract Attack_DigitalSignature {
    DigitalSignatureVuln public target;
    constructor(DigitalSignatureVuln _t) { target = _t; }

    function forge(bytes calldata message, bytes calldata fakeSig) external {
        target.verify(DigitalSignatureType.ECDSA, message, fakeSig);
    }

    function replay(bytes calldata message, bytes calldata signature) external {
        target.verify(DigitalSignatureType.ECDSA, message, signature);
    }
}

///─────────────────────────────────────────────────────────────────────────────
/// 3) SAFE ECDSA VERIFIER WITH NONCE PROTECTION
///
///    • Defense: SignatureValidation + NonceValidation  
///─────────────────────────────────────────────────────────────────────────────
contract DigitalSignatureSafe {
    mapping(bytes32 => bool) public usedNonce;
    event Verified(
        address indexed signer,
        bytes    message,
        bytes    signature,
        DigitalSignatureDefenseType defense
    );

    function verify(
        address signer,
        bytes calldata message,
        uint256 nonce,
        bytes calldata signature
    ) external {
        // nonce replay protection
        bytes32 nkey = keccak256(abi.encodePacked(signer, nonce));
        if (usedNonce[nkey]) revert DS__ReplayDetected();
        usedNonce[nkey] = true;

        // signature validation
        bytes32 msgHash = prefixed(keccak256(message));
        (uint8 v, bytes32 r, bytes32 s) = split(signature);
        address recovered = ecrecover(msgHash, v, r, s);
        if (recovered != signer) revert DS__InvalidSignature();

        emit Verified(signer, message, signature, DigitalSignatureDefenseType.SignatureValidation);
    }

    function prefixed(bytes32 hash) internal pure returns (bytes32) {
        return keccak256(abi.encodePacked("\x19Ethereum Signed Message:\n32", hash));
    }

    function split(bytes calldata sig) internal pure returns (uint8, bytes32, bytes32) {
        require(sig.length == 65, "bad signature length");
        bytes32 r;
        bytes32 s;
        uint8 v;
        assembly {
            r := calldataload(sig.offset)
            s := calldataload(add(sig.offset, 32))
            v := byte(0, calldataload(add(sig.offset, 64)))
        }
        return (v, r, s);
    }
}

///─────────────────────────────────────────────────────────────────────────────
/// 4) SAFE MULTI‑SIGNATURE VERIFIER (THRESHOLD)
///
///    • Defense: MultiSignature  
///─────────────────────────────────────────────────────────────────────────────
contract DigitalSignatureSafeMulti {
    uint256 public threshold;
    mapping(address => bool) public isSigner;

    event VerifiedMulti(
        bytes    message,
        address[] signers,
        DigitalSignatureDefenseType defense
    );

    constructor(address[] memory signers, uint256 _threshold) {
        require(signers.length >= _threshold, "threshold too high");
        threshold = _threshold;
        for (uint256 i = 0; i < signers.length; i++) {
            isSigner[signers[i]] = true;
        }
    }

    function verifyMulti(
        bytes calldata message,
        bytes[] calldata signatures,
        address[] calldata signers
    ) external {
        if (signatures.length < threshold) revert DS__InsufficientSignatures();
        bytes32 msgHash = prefixed(keccak256(message));
        uint256 validCount;
        for (uint256 i = 0; i < signatures.length; i++) {
            address s = signers[i];
            if (!isSigner[s]) revert DS__NotSigner();
            (uint8 v, bytes32 r, bytes32 sPart) = split(signatures[i]);
            address recovered = ecrecover(msgHash, v, r, sPart);
            if (recovered == s) {
                validCount++;
            }
        }
        if (validCount < threshold) revert DS__InsufficientSignatures();
        emit VerifiedMulti(message, signers, DigitalSignatureDefenseType.MultiSignature);
    }

    function prefixed(bytes32 hash) internal pure returns (bytes32) {
        return keccak256(abi.encodePacked("\x19Ethereum Signed Message:\n32", hash));
    }

    function split(bytes calldata sig) internal pure returns (uint8, bytes32, bytes32) {
        require(sig.length == 65, "bad signature length");
        bytes32 r;
        bytes32 s;
        uint8 v;
        assembly {
            r := calldataload(sig.offset)
            s := calldataload(add(sig.offset, 32))
            v := byte(0, calldataload(add(sig.offset, 64)))
        }
        return (v, r, s);
    }
}
