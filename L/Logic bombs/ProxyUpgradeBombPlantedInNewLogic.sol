// SPDX-License-Identifier: MIT
pragma solidity ^0.8.21;

contract ProxyAdmin {
    address public owner = msg.sender;
    address public implementation;

    function upgrade(address newImpl) external {
        require(msg.sender == owner, "Not admin");
        implementation = newImpl;
    }

    fallback() external payable {
        address impl = implementation;
        require(impl != address(0), "No logic yet");

        assembly {
            calldatacopy(0, 0, calldatasize())
            let result := delegatecall(gas(), impl, 0, calldatasize(), 0, 0)
            returndatacopy(0, 0, returndatasize())
            switch result
            case 0 { revert(0, returndatasize()) }
            default { return(0, returndatasize()) }
        }
    }
}
