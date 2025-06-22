// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/// Attack Types: Network Exploit, Proxy Drift, Insider Misuse
/// Defense Types: Vector Enforcement, Role Check, Context Restriction

contract AccessVectorEnforcer {
    address public admin;
    address public relay;

    enum AccessVector { NONE, LOCAL, ADJACENT, NETWORK }

    event VectorAccessGranted(address indexed user, AccessVector vector, string functionId);
    event AttackDetected(address indexed user, string reason);

    modifier onlyAdmin() {
        require(msg.sender == admin, "Admin only");
        _;
    }

    constructor(address _relay) {
        admin = msg.sender;
        relay = _relay;
    }

    /// NETWORK Vector — open to everyone
    function networkAccessible() external returns (string memory) {
        emit VectorAccessGranted(msg.sender, AccessVector.NETWORK, "networkAccessible");
        return "Access via NETWORK vector granted.";
    }

    /// ADJACENT Vector — only router/relay allowed
    function adjacentAccessible() external returns (string memory) {
        if (msg.sender != relay) {
            emit AttackDetected(msg.sender, "Unauthorized ADJACENT vector access");
            revert("Access denied: not relay");
        }
        emit VectorAccessGranted(msg.sender, AccessVector.ADJACENT, "adjacentAccessible");
        return "Access via ADJACENT vector granted.";
    }

    /// LOCAL Vector — only admin or key-holding signer
    function localAccessible() external returns (string memory) {
        if (msg.sender != admin) {
            emit AttackDetected(msg.sender, "Unauthorized LOCAL vector access");
            revert("Access denied: not local admin");
        }
        emit VectorAccessGranted(msg.sender, AccessVector.LOCAL, "localAccessible");
        return "Access via LOCAL vector granted.";
    }

    /// ATTACK Simulation: Call all vectors with unauthorized actor
    function attackAllVectors() external {
        if (msg.sender != admin && msg.sender != relay) {
            emit AttackDetected(msg.sender, "Simulated vector abuse attempt");
            revert("Attack simulation");
        }
    }

    /// View access vector type (for external scoring systems)
    function getAccessVector(string calldata fn) external pure returns (AccessVector) {
        if (keccak256(bytes(fn)) == keccak256("networkAccessible")) return AccessVector.NETWORK;
        if (keccak256(bytes(fn)) == keccak256("adjacentAccessible")) return AccessVector.ADJACENT;
        if (keccak256(bytes(fn)) == keccak256("localAccessible")) return AccessVector.LOCAL;
        return AccessVector.NONE;
    }
}
