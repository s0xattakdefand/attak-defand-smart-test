// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/**
 * @title OpenRouter
 * @notice Routes any call to any target (DANGEROUS).
 */
contract OpenRouter {
    function route(address target, bytes calldata data) external returns (bytes memory) {
        (bool success, bytes memory result) = target.call(data);
        require(success, "Call failed");
        return result;
    }
}
