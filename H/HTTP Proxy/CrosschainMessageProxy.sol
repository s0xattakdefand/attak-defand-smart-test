contract ChainGatewayProxy {
    mapping(bytes32 => bool) public processed;

    function relay(bytes32 msgId, address target, bytes calldata data) external {
        require(!processed[msgId], "Already relayed");
        processed[msgId] = true;

        (bool ok, ) = target.call(data);
        require(ok, "Relay failed");
    }
}
