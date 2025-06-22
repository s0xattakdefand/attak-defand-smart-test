contract CrossChainBroadcaster {
    event CrossChainMessage(address indexed user, string payload, string targetChain);

    function broadcastCrossChain(string calldata payload, string calldata targetChain) external {
        emit CrossChainMessage(msg.sender, payload, targetChain);
    }
}
