// SPDX-License-Identifier: MIT
pragma solidity ^0.8.21;

contract FakeMD5Handler {
    function spoof(bytes16 hash) external {
        // Fakes a commit by writing to victim storage
        assembly {
            sstore(hash, caller())
        }
    }
}
