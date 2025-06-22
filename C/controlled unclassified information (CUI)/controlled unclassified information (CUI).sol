// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "@openzeppelin/contracts/access/AccessControl.sol";

contract CUIProtectedStorage is AccessControl {
    bytes32 public constant INFO_WRITER = keccak256("INFO_WRITER");
    mapping(bytes32 => bytes32) private secureData; // keyHash => dataHash

    event CUIStored(bytes32 indexed keyHash, address indexed by);
    event AccessDenied(address indexed by, string reason);

    constructor(address admin) {
        _grantRole(DEFAULT_ADMIN_ROLE, admin);
        _grantRole(INFO_WRITER, admin);
    }

    /// @notice Store CUI (hashed key and value)
    function storeCUI(bytes32 keyHash, bytes32 valueHash) external onlyRole(INFO_WRITER) {
        secureData[keyHash] = valueHash;
        emit CUIStored(keyHash, msg.sender);
    }

    /// @notice Read CUI value (only admin)
    function getCUI(bytes32 keyHash) external view onlyRole(DEFAULT_ADMIN_ROLE) returns (bytes32) {
        return secureData[keyHash];
    }

    /// @notice Reject public access
    fallback() external payable {
        emit AccessDenied(msg.sender, "fallback");
        revert("Denied");
    }

    receive() external payable {
        emit AccessDenied(msg.sender, "ether rejected");
        revert("No Ether");
    }
}
