// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/**
 * ATTACK TYPE:
 * A naive echo request function that calls back into the sender's contract 
 * or logs data with no limit. Attackers can spam or re-enter.
 */
contract NaiveEchoRequest {
    event EchoRequestReceived(address indexed sender, string message);

    /**
     * @dev The user sends a request, we simply log or do a callback 
     * with no protective measures => reentrancy or spam risk.
     */
    function echoRequest(string calldata message) external {
        // ❌ Attack: no limit or guard => spamming or reentrancy possible 
        emit EchoRequestReceived(msg.sender, message);
        
        // Potentially calls back to the sender in some expansions => reentrancy
        // (omitted here but imagine if we do: ICaller(msg.sender).someCallback();
    }
}
