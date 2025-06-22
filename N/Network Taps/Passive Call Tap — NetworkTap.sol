// SPDX-License-Identifier: MIT
pragma solidity ^0.8.21;

contract NetworkTap {
    event TapLog(address indexed from, address indexed to, bytes4 selector, bytes data);

    function tap(address target, bytes calldata data) external {
        bytes4 selector;
        assembly { selector := calldataload(data.offset) }
        emit TapLog(msg.sender, target, selector, data);
        (bool ok, ) = target.call(data);
        require(ok, "Tap call failed");
    }
}
