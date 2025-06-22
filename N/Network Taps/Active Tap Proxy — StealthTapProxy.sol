contract StealthTapProxy {
    address public immutable tap;
    address public immutable implementation;

    constructor(address _tap, address _impl) {
        tap = _tap;
        implementation = _impl;
    }

    fallback() external payable {
        (bool logged, ) = tap.call(
            abi.encodeWithSignature("tap(address,bytes)", implementation, msg.data)
        );
        require(logged, "Tap failed");

        (bool ok, ) = implementation.delegatecall(msg.data);
        require(ok, "Execution failed");
    }
}
