// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

contract BitFlagsSecure {
    mapping(address => uint8) public flags;

    uint8 constant IS_ADMIN = 0x01;
    uint8 constant CAN_MINT = 0x02;
    uint8 constant CAN_BURN = 0x04;

    event FlagUpdated(address indexed user, uint8 newFlags);

    modifier hasFlag(address user, uint8 flag) {
        require((flags[user] & flag) == flag, "Access denied");
        _;
    }

    function setFlag(address user, uint8 flag) public {
        flags[user] |= flag;
        emit FlagUpdated(user, flags[user]);
    }

    function clearFlag(address user, uint8 flag) public {
        flags[user] &= ~flag;
        emit FlagUpdated(user, flags[user]);
    }

    function mint() public hasFlag(msg.sender, CAN_MINT) {
        // Secure logic: only users with CAN_MINT bit can mint
    }

    function burn() public hasFlag(msg.sender, CAN_BURN) {
        // Only users with CAN_BURN bit
    }

    function isAdmin(address user) public view returns (bool) {
        return (flags[user] & IS_ADMIN) == IS_ADMIN;
    }
}
