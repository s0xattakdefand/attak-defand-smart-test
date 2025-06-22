contract SelectorProxy {
    mapping(bytes4 => address) public targets;

    function register(bytes4 sel, address handler) external {
        targets[sel] = handler;
    }

    fallback() external {
        address t = targets[msg.sig];
        require(t != address(0), "No handler");
        _delegate(t);
    }

    function _delegate(address impl) internal {
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
