// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "@openzeppelin/contracts/access/Ownable.sol";

/**
 * A safer gateway:
 * - validates input length
 * - optional role-based or signature-based checks
 * - sanitized storage or limited calls
 */
contract SecureGateway is Ownable {
    event GatewayProcess(address indexed caller, string request, string response);

    uint256 public maxLength = 100; // limit input size

    constructor(address initialOwner) Ownable(initialOwner) {
        // Optionally set a custom length or other initialization
    }

    function setMaxLength(uint256 len) external onlyOwner {
        maxLength = len;
    }

    function gatewayProcess(string calldata input) external returns (string memory) {
        require(bytes(input).length <= maxLength, "Input too large");
        // minimal transform
        string memory output = string(abi.encodePacked("Processed: ", input));

        // Log it
        emit GatewayProcess(msg.sender, input, output);

        return output;
    }
}
