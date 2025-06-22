// SPDX-License-Identifier: MIT
pragma solidity ^0.8.21;

/* ========== 1️⃣ Public Key ↔ Identity Registry ========== */
contract PublicKeyRegistry {
    struct Key {
        address owner;
        uint256 expiry;
        bool revoked;
    }

    mapping(bytes32 => Key) public keyInfo;

    event KeyRegistered(bytes32 indexed pubKeyHash, address indexed owner);
    event KeyRevoked(bytes32 indexed pubKeyHash);

    function registerKey(bytes32 pubKeyHash, uint256 expiry, bytes memory sig) external {
        require(keyInfo[pubKeyHash].owner == address(0), "Already exists");
        address signer = recover(pubKeyHash, sig);
        require(signer == msg.sender, "Signature mismatch");
        keyInfo[pubKeyHash] = Key(msg.sender, expiry, false);
        emit KeyRegistered(pubKeyHash, msg.sender);
    }

    function revokeKey(bytes32 pubKeyHash) external {
        require(keyInfo[pubKeyHash].owner == msg.sender, "Not owner");
        keyInfo[pubKeyHash].revoked = true;
        emit KeyRevoked(pubKeyHash);
    }

    function isValid(bytes32 pubKeyHash) public view returns (bool) {
        Key memory k = keyInfo[pubKeyHash];
        return k.owner != address(0) && !k.revoked && block.timestamp < k.expiry;
    }

    function recover(bytes32 hash, bytes memory sig) public pure returns (address) {
        (bytes32 r, bytes32 s, uint8 v) = abi.decode(sig, (bytes32, bytes32, uint8));
        return ecrecover(hash, v, r, s);
    }
}

/* ========== 2️⃣ Role-Based CA for Cert Issuance ========== */
contract CertificateAuthority {
    address public issuer;

    mapping(address => string) public roles;
    event RoleIssued(address indexed user, string role);

    constructor() {
        issuer = msg.sender;
    }

    function issueRole(address user, string calldata role) external {
        require(msg.sender == issuer, "Not authorized");
        roles[user] = role;
        emit RoleIssued(user, role);
    }
}

/* ========== 3️⃣ zkProof Binding to PKI Root (Mocked) ========== */
contract ZKIdentityVerifier {
    mapping(bytes32 => bool) public validZKRoots;

    function bindZKRoot(bytes32 root) external {
        validZKRoots[root] = true;
    }

    function verifyZKRoot(bytes32 root) public view returns (bool) {
        return validZKRoots[root];
    }
}
