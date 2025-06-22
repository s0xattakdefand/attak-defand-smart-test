// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "@openzeppelin/contracts/access/AccessControl.sol";
import "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";

contract ControlledInterfaceExample is AccessControl {
    using ECDSA for bytes32;

    bytes32 public constant INTERFACE_ROLE = keccak256("INTERFACE_ROLE");
    address public oracle;
    mapping(bytes32 => bool) public usedHashes;

    event ActionExecuted(address caller);
    event OracleUpdated(address newOracle);

    constructor(address _oracle) {
        _grantRole(DEFAULT_ADMIN_ROLE, msg.sender);
        _grantRole(INTERFACE_ROLE, msg.sender);
        oracle = _oracle;
    }

    /// @notice Controlled access with role
    function interfaceAction() external onlyRole(INTERFACE_ROLE) {
        emit ActionExecuted(msg.sender);
    }

    /// @notice Signature-gated interface
    function signatureAccess(string calldata data, bytes calldata sig) external {
        bytes32 digest = keccak256(abi.encodePacked(data, msg.sender)).toEthSignedMessageHash();
        require(!usedHashes[digest], "Replay detected");
        require(digest.recover(sig) == oracle, "Invalid oracle sig");

        usedHashes[digest] = true;
        emit ActionExecuted(msg.sender);
    }

    /// @notice Admin can rotate oracle
    function updateOracle(address newOracle) external onlyRole(DEFAULT_ADMIN_ROLE) {
        oracle = newOracle;
        emit OracleUpdated(newOracle);
    }

    /// @notice Fallback selector filter
    fallback() external payable {
        bytes4 allowedSelector = bytes4(keccak256("interfaceAction()"));
        require(msg.sig == allowedSelector, "Invalid selector fallback");
    }

    receive() external payable {}
}
