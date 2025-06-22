contract CrossChainHopHandler {
    mapping(bytes32 => bool) public executed;

    event Routed(bytes32 msgHash, address finalTarget);

    function relay(bytes32 msgHash, address finalTarget, bytes calldata data) external {
        require(!executed[msgHash], "Already processed");
        executed[msgHash] = true;

        (bool ok, ) = finalTarget.call(data);
        require(ok, "Hop execution failed");

        emit Routed(msgHash, finalTarget);
    }
}
