// SPDX-License-Identifier: MIT
pragma solidity ^0.8.21;

/// @title DelegateProxyVictim - Calls external logic via delegatecall
contract DelegateProxyVictim {
    address public implementation;
    address public admin;

    constructor(address _impl) {
        implementation = _impl;
        admin = msg.sender;
    }

    function upgrade(address newImpl) external {
        require(msg.sender == admin, "Only admin");
        implementation = newImpl;
    }

    fallback() external payable {
        address impl = implementation;
        require(impl != address(0), "No implementation");

        assembly {
            calldatacopy(0, 0, calldatasize())
            let success := delegatecall(gas(), impl, 0, calldatasize(), 0, 0)
            returndatacopy(0, 0, returndatasize())
            switch success
                case 0 {
                    revert(0, returndatasize())
                }
                default {
                    return(0, returndatasize())
                }
        }
    }

    receive() external payable {}
}
