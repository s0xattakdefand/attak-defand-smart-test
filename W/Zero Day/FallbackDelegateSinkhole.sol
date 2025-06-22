contract FallbackDelegateSinkhole {
    address public logic;

    constructor(address _logic) {
        logic = _logic;
    }

    fallback() external {
        assembly {
            let ptr := mload(0x40)
            calldatacopy(ptr, 0, calldatasize())
            let ok := delegatecall(gas(), sload(logic.slot), ptr, calldatasize(), 0, 0)
            if iszero(ok) { revert(0, 0) }
        }
    }
}
