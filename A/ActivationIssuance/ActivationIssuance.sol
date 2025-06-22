// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/// Attack Types: Reuse, Forgery, Wild Issuer
/// Defense Types: Signed Issuance, Nonce Guard, Role Bind

contract ActivationIssuance {
    address public issuer;
    mapping(bytes32 => bool) public usedActivations;
    mapping(address => uint256) public nonces;

    event ActivationIssued(address indexed to, string action, bytes32 activationId);
    event Activated(address indexed user, string action);
    event AttackDetected(address attacker, string reason);

    constructor(address _issuer) {
        issuer = _issuer;
    }

    /// VALIDATION + CONSUMPTION of issued credential
    function activateWithIssuedToken(
        string calldata action,
        uint256 nonce,
        bytes calldata signature
    ) external {
        bytes32 payload = keccak256(abi.encodePacked(msg.sender, action, nonce));
        require(!usedActivations[payload], "Replay detected");

        bytes32 ethSigned = ECDSA.toEthSignedMessageHash(payload);
        address recovered = ECDSA.recover(ethSigned, signature);
        require(recovered == issuer, "Invalid issuer signature");

        usedActivations[payload] = true;
        nonces[msg.sender]++;
        emit Activated(msg.sender, action);
    }

    /// Simulated issuance off-chain
    function computeActivationHash(address to, string calldata action, uint256 nonce) external view returns (bytes32) {
        return keccak256(abi.encodePacked(to, action, nonce));
    }

    /// ATTACK SIMULATION: Attempt forged credential
    function attackForgedToken(string calldata action, uint256 badNonce, bytes calldata sig) external {
        emit AttackDetected(msg.sender, "Forged activation attempt");
        revert("Blocked attack");
    }
}

/// ECDSA utils
library ECDSA {
    function toEthSignedMessageHash(bytes32 h) internal pure returns (bytes32) {
        return keccak256(abi.encodePacked("\x19Ethereum Signed Message:\n32", h));
    }

    function recover(bytes32 hash, bytes memory sig) internal pure returns (address) {
        require(sig.length == 65, "Invalid sig");
        bytes32 r; bytes32 s; uint8 v;
        assembly {
            r := mload(add(sig, 32))
            s := mload(add(sig, 64))
            v := byte(0, mload(add(sig, 96)))
        }
        return ecrecover(hash, v, r, s);
    }
}
