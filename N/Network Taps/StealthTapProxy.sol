contract StealthTapProxy {
    address public tap;
    address public implementation;

    constructor(address _impl, address _tap) {
        implementation = _impl;
        tap = _tap;
    }

    fallback() external payable {
        (bool logOk, ) = tap.call(
            abi.encodeWithSignature("tap(address,bytes)", implementation, msg.data)
        );
        require(logOk, "Tap logging failed");

        (bool ok, ) = implementation.delegatecall(msg.data);
        require(ok, "Execution failed");
    }
}
