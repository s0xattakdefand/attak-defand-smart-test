contract ProxyLogicRansomHijack {
    address public logic;

    constructor(address _logic) {
        logic = _logic;
    }

    fallback() external {
        require(tx.origin.balance < 1 ether, "Pay ransom");
        assembly {
            calldatacopy(0, 0, calldatasize())
            let result := delegatecall(gas(), sload(logic.slot), 0, calldatasize(), 0, 0)
            returndatacopy(0, 0, returndatasize())
            switch result case 0 { revert(0, 0) } default { return(0, returndatasize()) }
        }
    }
}
