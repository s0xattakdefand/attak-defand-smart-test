contract CallGraphLogger {
    event CallLogged(address indexed caller, address indexed callee, bytes4 selector);

    function logCall(address callee, bytes calldata data) external {
        bytes4 selector;
        assembly {
            selector := calldataload(data.offset)
        }
        emit CallLogged(msg.sender, callee, selector);
        (bool ok, ) = callee.call(data);
        require(ok, "Call failed");
    }
}
