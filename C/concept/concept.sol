// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import "@openzeppelin/contracts/security/ReentrancyGuard.sol";
import "@openzeppelin/contracts/access/AccessControl.sol";

contract ConceptGuard is ReentrancyGuard, AccessControl {
    bytes32 public constant OPERATOR_ROLE = keccak256("OPERATOR_ROLE");
    mapping(bytes32 => bool) public usedHashes;

    event ConceptUsed(address indexed actor, string concept, bytes32 hash);

    constructor() {
        _setupRole(DEFAULT_ADMIN_ROLE, msg.sender);
        _setupRole(OPERATOR_ROLE, msg.sender);
    }

    function executeConcept(string calldata concept, bytes calldata payload, bytes32 uniqueHash)
        external
        nonReentrant
        onlyRole(OPERATOR_ROLE)
    {
        require(!usedHashes[uniqueHash], "Replay detected");
        usedHashes[uniqueHash] = true;

        // Simulate conceptual operation
        emit ConceptUsed(msg.sender, concept, uniqueHash);
        (bool ok, ) = address(this).call(payload);
        require(ok, "Execution failed");
    }

    function resetConcept(bytes32 hash) external onlyRole(DEFAULT_ADMIN_ROLE) {
        usedHashes[hash] = false;
    }
}
