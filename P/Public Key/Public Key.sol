// SPDX-License-Identifier: MIT
pragma solidity ^0.8.21;

/* ========== 1️⃣ Signature Verification ========== */
contract SigVerifier {
    function recover(bytes32 hash, bytes memory sig) public pure returns (address) {
        (bytes32 r, bytes32 s, uint8 v) = abi.decode(sig, (bytes32, bytes32, uint8));
        return ecrecover(hash, v, r, s);
    }

    function toEthSigned(bytes32 h) public pure returns (bytes32) {
        return keccak256(abi.encodePacked("\x19Ethereum Signed Message:\n32", h));
    }
}

/* ========== 2️⃣ Permit-Based Auth (Nonce-bound) ========== */
contract PermitAuth {
    mapping(address => uint256) public nonces;

    function permit(address user, string calldata action, uint256 nonce, bytes memory sig) external view returns (bool) {
        require(nonce == nonces[user], "Invalid nonce");
        bytes32 hash = keccak256(abi.encodePacked(user, action, nonce));
        address signer = SigVerifier(address(this)).recover(hash, sig);
        return signer == user;
    }

    function useNonce(address user) external {
        nonces[user]++;
    }
}

/* ========== 3️⃣ Public Key Registry (Self-binding) ========== */
contract PublicKeyRegistry {
    mapping(address => bytes32) public pubKeys;

    function registerPubKey(bytes32 pubHash) external {
        pubKeys[msg.sender] = pubHash;
    }

    function isValid(address user, bytes32 pubHash) external view returns (bool) {
        return pubKeys[user] == pubHash;
    }
}

/* ========== 4️⃣ Role-Based Signature Check ========== */
contract RoleSigCheck {
    mapping(address => string) public roles;

    function assignRole(address user, string calldata role) external {
        roles[user] = role;
    }

    function checkRoleSig(string calldata action, string calldata requiredRole, bytes memory sig) external view returns (bool) {
        bytes32 hash = keccak256(abi.encodePacked(action, requiredRole));
        address signer = SigVerifier(address(this)).recover(hash, sig);
        return keccak256(bytes(roles[signer])) == keccak256(bytes(requiredRole));
    }
}
