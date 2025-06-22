// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

contract SelfBinding {
    mapping(address => string) public usernames;

    event UsernameBound(address indexed user, string username);

    /**
     * @notice Allows a user to bind a username to their address.
     * @param name The username to bind.
     */
    function bindUsername(string calldata name) public {
        usernames[msg.sender] = name;
        emit UsernameBound(msg.sender, name);
    }

    /**
     * @notice Retrieve your own username.
     */
    function getMyUsername() public view returns (string memory) {
        return usernames[msg.sender];
    }
}
