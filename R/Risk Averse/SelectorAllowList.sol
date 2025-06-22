contract SelectorAllowlist {
    mapping(bytes4 => bool) public allowed;

    fallback() external {
        require(allowed[msg.sig], "Selector not approved");
        assembly {
            let result := delegatecall(gas(), sload(0x0), 0, calldatasize(), 0, 0)
            returndatacopy(0, 0, returndatasize())
            if iszero(result) { revert(0, returndatasize()) }
            return(0, returndatasize())
        }
    }

    function allow(bytes4 sig) external {
        allowed[sig] = true;
    }
}
