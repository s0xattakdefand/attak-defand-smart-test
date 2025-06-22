// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

contract OnChainFlaggingSystem {
    mapping(address => bool) public flagged;
    address public admin;

    event UserFlagged(address indexed user, string reason);
    event UserUnflagged(address indexed user);

    constructor() {
        admin = msg.sender;
    }

    modifier onlyAdmin() {
        require(msg.sender == admin, "Not authorized");
        _;
    }

    /**
     * @notice Flag a suspicious address on-chain.
     * @param user The address to be flagged.
     * @param reason A short description for flagging.
     */
    function flag(address user, string calldata reason) public onlyAdmin {
        flagged[user] = true;
        emit UserFlagged(user, reason);
    }

    /**
     * @notice Unflag a previously flagged address.
     */
    function unflag(address user) public onlyAdmin {
        flagged[user] = false;
        emit UserUnflagged(user);
    }

    /**
     * @notice Check if an address is flagged.
     */
    function isFlagged(address user) public view returns (bool) {
        return flagged[user];
    }
}
