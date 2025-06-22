contract CrossChainHub {
    mapping(bytes32 => bool) public executed;

    function receiveMessage(bytes32 id, address target, bytes calldata payload) external {
        require(!executed[id], "Already processed");
        executed[id] = true;

        // Validate msg.sender is trusted relayer (not shown for simplicity)

        (bool ok, ) = target.call(payload);
        require(ok, "Execution failed");
    }
}
