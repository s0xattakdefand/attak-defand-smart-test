// SPDX-License-Identifier: MIT
pragma solidity ^0.8.21;

contract NullSessionAccess {
    event Accessed(address indexed caller);

    function viewVaultContents() external {
        emit Accessed(msg.sender); // ❌ No access control = null session risk
    }
}
