// SPDX-License-Identifier: MIT
pragma solidity ^0.8.21;

/* ========== 1️⃣ Ephemeral Signature Validator ========== */
contract EphemeralSigPFS {
    mapping(bytes32 => bool) public usedHash;

    function verifyOnce(bytes32 hash, bytes memory sig) public returns (address) {
        require(!usedHash[hash], "Used signature");
        usedHash[hash] = true;

        (bytes32 r, bytes32 s, uint8 v) = abi.decode(sig, (bytes32, bytes32, uint8));
        return ecrecover(hash, v, r, s);
    }
}

/* ========== 2️⃣ Time-Locked Public Key Rotation ========== */
contract KeyRotationPFS {
    struct PubKey {
        address key;
        uint256 expires;
    }

    mapping(address => PubKey[]) public keychain;

    function addEphemeralKey(address user, address key, uint256 duration) external {
        keychain[user].push(PubKey(key, block.timestamp + duration));
    }

    function isValid(address user, address key) external view returns (bool) {
        PubKey[] memory keys = keychain[user];
        for (uint256 i = 0; i < keys.length; i++) {
            if (keys[i].key == key && block.timestamp < keys[i].expires) {
                return true;
            }
        }
        return false;
    }
}

/* ========== 3️⃣ Session-Salted Signature Hash ========== */
contract SaltedSessionPFS {
    mapping(address => bytes32) public latestSalt;

    function rotateSession(address user, bytes32 salt) external {
        latestSalt[user] = salt;
    }

    function validateSig(address user, string calldata action, bytes memory sig) public view returns (bool) {
        bytes32 hash = keccak256(abi.encodePacked(user, latestSalt[user], action));
        address signer = recover(hash, sig);
        return signer == user;
    }

    function recover(bytes32 h, bytes memory sig) internal pure returns (address) {
        (bytes32 r, bytes32 s, uint8 v) = abi.decode(sig, (bytes32, bytes32, uint8));
        return ecrecover(h, v, r, s);
    }
}
