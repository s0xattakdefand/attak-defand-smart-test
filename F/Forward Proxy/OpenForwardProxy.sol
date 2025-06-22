// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/**
 * @title OpenForwardProxy
 * @notice Forwards any user call to any target. ⚠️ Dangerous.
 */
contract OpenForwardProxy {
    function forward(address target, bytes calldata data) external returns (bytes memory) {
        (bool success, bytes memory result) = target.call(data);
        require(success, "Forward failed");
        return result;
    }
}
