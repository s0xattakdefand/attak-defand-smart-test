// SPDX-License-Identifier: MIT
pragma solidity ^0.8.25;

contract AppSpecificKDF {
    event DerivedKey(bytes32 key, address indexed user, string context);

    function deriveAppKey(address user, string calldata context) external pure returns (bytes32) {
        return keccak256(abi.encodePacked("KDF:", context, user));
    }

    function testDerivation(address user, string calldata context) external returns (bytes32) {
        bytes32 derived = deriveAppKey(user, context);
        emit DerivedKey(derived, user, context);
        return derived;
    }
}
