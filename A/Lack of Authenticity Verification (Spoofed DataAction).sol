// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

contract FakeDataReceiver {
    string public verifiedName;

    // ❌ Accepts data blindly without authenticity check
    function updateName(string calldata name) public {
        verifiedName = name;
    }
}
