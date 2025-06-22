// SPDX-License-Identifier: MIT
pragma solidity ^0.8.21;

/// @title MD5CollisionTrap - Validates user input using weak MD5 hash
contract MD5CollisionTrap {
    mapping(bytes16 => address) public submissions;

    function submit(bytes16 md5hash) external {
        require(submissions[md5hash] == address(0), "Already used");
        submissions[md5hash] = msg.sender;
    }

    function verify(bytes16 md5hash) external view returns (bool) {
        return submissions[md5hash] != address(0);
    }
}
