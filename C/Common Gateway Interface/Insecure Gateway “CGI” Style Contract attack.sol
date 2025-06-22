// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/**
 * A naive contract that acts like a CGI-style gateway, forwarding user input
 * without checks or limiting external calls
 */
contract InsecureGateway {
    event GatewayLog(string request, string response);

    function gatewayProcess(string calldata input) external returns (string memory) {
        // ❌ Directly trust user input, no validation
        // Potentially pass to external calls or store as-is
        string memory output = string(abi.encodePacked("Echo: ", input));

        // If it triggered an external call with user content, could be vulnerable
        emit GatewayLog(input, output);

        return output;
    }
}
