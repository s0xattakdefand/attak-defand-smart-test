// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "@openzeppelin/contracts/access/AccessControl.sol";
import "@openzeppelin/contracts/security/ReentrancyGuard.sol";
import "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";

/// @title ControlledAccessProtector — Strong layered access protection
contract ControlledAccessProtector is AccessControl, ReentrancyGuard {
    using ECDSA for bytes32;

    bytes32 public constant ADMIN_ROLE = keccak256("ADMIN_ROLE");
    address public trustedSigner;

    mapping(address => uint256) public sessionExpiry;

    event ProtectedActionTriggered(address indexed user, string label);
    event SessionActivated(address indexed user, uint256 expiresAt);

    modifier onlyAdmin() {
        require(hasRole(ADMIN_ROLE, msg.sender), "Access denied: Not admin");
        _;
    }

    modifier validSession(bytes32 hash, bytes memory sig, uint256 expiresAt) {
        require(block.timestamp <= expiresAt, "Session expired");
        require(sessionExpiry[msg.sender] < expiresAt, "Session already used");
        require(hash.toEthSignedMessageHash().recover(sig) == trustedSigner, "Invalid signer");
        sessionExpiry[msg.sender] = expiresAt;
        emit SessionActivated(msg.sender, expiresAt);
        _;
    }

    constructor(address admin, address signer) {
        _grantRole(DEFAULT_ADMIN_ROLE, admin);
        _grantRole(ADMIN_ROLE, admin);
        trustedSigner = signer;
    }

    /// ✅ Protected admin logic with session + role + reentrancy guard
    function protectedAdminAction(
        string calldata label,
        uint256 expiresAt,
        bytes calldata sig
    )
        external
        nonReentrant
        onlyAdmin
        validSession(keccak256(abi.encodePacked(msg.sender, label, expiresAt)), sig, expiresAt)
    {
        emit ProtectedActionTriggered(msg.sender, label);
        // Insert secure logic here...
    }

    function updateSigner(address newSigner) external onlyAdmin {
        trustedSigner = newSigner;
    }
}
