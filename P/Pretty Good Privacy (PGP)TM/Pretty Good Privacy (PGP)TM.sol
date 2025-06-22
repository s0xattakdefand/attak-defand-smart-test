// SPDX-License-Identifier: MIT
pragma solidity ^0.8.21;

/* ========== 1️⃣ Public Key Binding Registry ========== */
contract PublicKeyRegistry {
    mapping(address => bytes32) public pubKeyHash;

    function register(bytes32 keyHash) external {
        pubKeyHash[msg.sender] = keyHash;
    }

    function isValid(address user, bytes32 pubHash) external view returns (bool) {
        return pubKeyHash[user] == pubHash;
    }
}

/* ========== 2️⃣ On-Chain Message Signature Verification ========== */
contract PGPVerify {
    function verify(bytes32 digest, bytes memory sig) external pure returns (address) {
        (bytes32 r, bytes32 s, uint8 v) = abi.decode(sig, (bytes32, bytes32, uint8));
        return ecrecover(digest, v, r, s);
    }

    function toEthSigned(bytes32 h) public pure returns (bytes32) {
        return keccak256(abi.encodePacked("\x19Ethereum Signed Message:\n32", h));
    }
}

/* ========== 3️⃣ Message Nonce Guard (Replay Protection) ========== */
contract SigNonceGuard {
    mapping(address => mapping(bytes32 => bool)) public used;

    function check(bytes32 hash, bytes memory sig) external returns (address) {
        address signer = PGPVerify(address(this)).verify(hash, sig);
        require(!used[signer][hash], "Replay detected");
        used[signer][hash] = true;
        return signer;
    }
}

/* ========== 4️⃣ Timestamp-Bound Signature (Time-Locked Message) ========== */
contract TimestampedSig {
    function validate(bytes32 message, uint256 expiry, bytes memory sig) external view returns (bool) {
        require(block.timestamp <= expiry, "Expired");
        bytes32 full = keccak256(abi.encodePacked(message, expiry));
        address recovered = PGPVerify(address(this)).verify(full, sig);
        return recovered != address(0);
    }
}

/* ========== 5️⃣ Hybrid Message Proof (Digest + Domain Separator) ========== */
contract DomainBoundPGP {
    string public domain = "pgp.web3.secure";

    function validate(bytes memory msgData, bytes memory sig) public view returns (address) {
        bytes32 digest = keccak256(abi.encodePacked(domain, msgData));
        return PGPVerify(address(this)).verify(digest, sig);
    }
}
