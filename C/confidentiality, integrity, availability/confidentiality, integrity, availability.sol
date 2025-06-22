// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import "@openzeppelin/contracts/access/AccessControl.sol";
import "@openzeppelin/contracts/security/Pausable.sol";

contract CIAGuard is AccessControl, Pausable {
    bytes32 public constant OPERATOR_ROLE = keccak256("OPERATOR_ROLE");
    mapping(bytes32 => bool) public usedHashes;
    mapping(address => bool) public trustedCallers;

    event ConfidentialAction(address indexed actor, bytes32 indexed nullifier);
    event IntegrityAction(address indexed actor, bytes32 indexed payloadHash);
    event AvailabilityBlocked(address indexed actor);

    constructor() {
        _setupRole(DEFAULT_ADMIN_ROLE, msg.sender);
        _setupRole(OPERATOR_ROLE, msg.sender);
    }

    modifier onlyTrusted() {
        require(trustedCallers[msg.sender], "Untrusted caller");
        _;
    }

    modifier preventReplay(bytes32 hash) {
        require(!usedHashes[hash], "Replay detected");
        usedHashes[hash] = true;
        _;
    }

    function performSecureAction(
        string calldata actionType,
        bytes32 nullifier,       // Confidentiality (unique secret)
        bytes32 payloadHash      // Integrity (operation validation)
    )
        external
        whenNotPaused
        onlyRole(OPERATOR_ROLE)
        onlyTrusted
        preventReplay(payloadHash)
    {
        emit ConfidentialAction(msg.sender, nullifier);
        emit IntegrityAction(msg.sender, payloadHash);
    }

    function blockCaller(address actor) external onlyRole(DEFAULT_ADMIN_ROLE) {
        trustedCallers[actor] = false;
        emit AvailabilityBlocked(actor);
    }

    function trustCaller(address actor) external onlyRole(DEFAULT_ADMIN_ROLE) {
        trustedCallers[actor] = true;
    }

    function pauseSystem() external onlyRole(DEFAULT_ADMIN_ROLE) {
        _pause();
    }

    function resumeSystem() external onlyRole(DEFAULT_ADMIN_ROLE) {
        _unpause();
    }
}
