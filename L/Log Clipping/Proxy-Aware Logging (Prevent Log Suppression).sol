contract LoggingProxy {
    address public implementation;
    event ProxyCall(address indexed caller, address indexed to, bytes data);

    function setImpl(address impl) external {
        implementation = impl;
    }

    fallback() external payable {
        emit ProxyCall(msg.sender, implementation, msg.data);

        assembly {
            calldatacopy(0, 0, calldatasize())
            let result := delegatecall(gas(), sload(implementation.slot), 0, calldatasize(), 0, 0)
            returndatacopy(0, 0, returndatasize())
            switch result
                case 0 { revert(0, returndatasize()) }
                default { return(0, returndatasize()) }
        }
    }
}
