// Executing arbitrary logic inside this contract’s storage
contract DelegateBackdoor {
    address public delegate;

    constructor(address _delegate) {
        delegate = _delegate;
    }

    function execute(bytes calldata data) external {
        // ❌ Dangerous delegatecall to external contract
        (bool success, ) = delegate.delegatecall(data);
        require(success, "Delegatecall failed");
    }
}
