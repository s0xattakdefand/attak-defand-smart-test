// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

contract ForestProxy {
    address public implementation;
    address public forestAdmin;

    constructor(address _impl) {
        implementation = _impl;
        forestAdmin = msg.sender;
    }

    function upgrade(address newImpl) external {
        require(msg.sender == forestAdmin, "Only forest admin");
        implementation = newImpl;
    }

    fallback() external payable {
        address impl = implementation;
        assembly {
            calldatacopy(0, 0, calldatasize())
            let result := delegatecall(gas(), impl, 0, calldatasize(), 0, 0)
            returndatacopy(0, 0, returndatasize())
            switch result
                case 0 {
                    revert(0, returndatasize())
                }
                default {
                    return(0, returndatasize())
                }
        }
    }
}
