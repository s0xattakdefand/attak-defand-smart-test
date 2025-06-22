// Transparent Proxy Kernel Skeleton
pragma solidity ^0.8.21;

contract KernelProxy {
    address public implementation;

    constructor(address _impl) {
        implementation = _impl;
    }

    fallback() external payable {
        address impl = implementation;
        assembly {
            calldatacopy(0, 0, calldatasize())
            let success := delegatecall(gas(), impl, 0, calldatasize(), 0, 0)
            returndatacopy(0, 0, returndatasize())
            switch success
            case 0 { revert(0, returndatasize()) }
            default { return(0, returndatasize()) }
        }
    }
}
