// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/**
 * Another approach:
 * We let users 'subscribe' to certain events, 
 * so we only emit for those who opted in (like event filtering).
 */
contract SelectiveEventSubscription {
    mapping(address => bool) public subscribed;

    event Subscribed(address user, bool status);
    event SubscribedData(address subscriber, bytes data);

    function setSubscription(bool status) external {
        subscribed[msg.sender] = status;
        emit Subscribed(msg.sender, status);
    }

    function pushData(bytes calldata data) external {
        require(subscribed[msg.sender], "Not subscribed");
        emit SubscribedData(msg.sender, data);
    }
}
