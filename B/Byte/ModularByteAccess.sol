// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";

interface IZKVerifier {
    function verifyProof(bytes calldata proof) external view returns (bool);
}

contract ModularByteAccess {
    using ECDSA for bytes32;

    enum BitRole {
        Admin,    // 0
        Minter,   // 1
        Burner,   // 2
        KYC,      // 3
        VIP       // 4
    }

    struct RoleData {
        bytes1 roles;     // up to 8 flags (bitmask)
        uint256 expires;  // global expiration
        uint256 nonce;    // EIP-712 replay protection
    }

    address public verifierSigner;  // off-chain verifier (for sigs)
    IZKVerifier public zkVerifier;  // zkSNARK circuit for proving bits
    mapping(address => RoleData) public userRoles;

    event RoleGranted(address indexed user, uint8 bit, uint256 expires);
    event RoleRevoked(address indexed user, uint8 bit);
    event ZKFlagVerified(address indexed user, uint8 bit);

    constructor(address _verifierSigner, address _zkVerifier) {
        verifierSigner = _verifierSigner;
        zkVerifier = IZKVerifier(_zkVerifier);
    }

    // --- BYTE-BASED ROLE EXPIRATION ---

    function hasRole(address user, uint8 bit) public view returns (bool) {
        if (block.timestamp > userRoles[user].expires) return false;
        return (userRoles[user].roles & bytes1(uint8(1 << bit))) != 0;
    }

    function grantRole(address user, uint8 bit, uint256 duration) public {
        require(bit < 8, "Invalid role");
        userRoles[user].roles |= bytes1(uint8(1 << bit));
        userRoles[user].expires = block.timestamp + duration;
        emit RoleGranted(user, bit, userRoles[user].expires);
    }

    function revokeRole(address user, uint8 bit) public {
        require(bit < 8, "Invalid role");
        userRoles[user].roles &= ~bytes1(uint8(1 << bit));
        emit RoleRevoked(user, bit);
    }

    // --- EIP-712 SIGNATURE GRANTING ---

    function grantRoleWithSig(address user, uint8 bit, uint256 duration, bytes calldata sig) external {
        require(bit < 8, "Invalid bit");
        uint256 nonce = userRoles[user].nonce++;

        bytes32 messageHash = keccak256(abi.encodePacked(user, bit, duration, nonce));
        bytes32 ethHash = messageHash.toEthSignedMessageHash();

        require(ethHash.recover(sig) == verifierSigner, "Invalid signer");
        userRoles[user].roles |= bytes1(uint8(1 << bit));
        userRoles[user].expires = block.timestamp + duration;

        emit RoleGranted(user, bit, userRoles[user].expires);
    }

    // --- ZK-PROOF MASKED ROLE VERIFICATION ---

    function verifyFlagWithZK(address user, uint8 bit, bytes calldata proof) public view returns (bool) {
        require(bit < 8, "Invalid bit");
        require(zkVerifier.verifyProof(proof), "ZK proof invalid");
        // Optional: emit event or store for audit
        return true;
    }
}
