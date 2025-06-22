// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/**
 * ATTACK TYPE:
 * A contract that lets a user specify any address to call externally, 
 * with no restrictions => malicious egress call is possible.
 */
contract NaiveEgressCall {
    event ExternalCall(address indexed target, bytes data, bool success);

    /**
     * @dev The user can specify any 'target' address and 'data' to call
     * => Attackers can force the contract to call a malicious or undesired address.
     */
    function callExternal(address target, bytes calldata data) external {
        // ❌ No egress filtering => any address can be called
        (bool success, ) = target.call(data);
        emit ExternalCall(target, data, success);
    }
}
