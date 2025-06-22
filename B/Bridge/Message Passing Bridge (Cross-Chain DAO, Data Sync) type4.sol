contract CrossChainMessenger {
    event MessageOut(address indexed sender, string data, string destinationChain);

    function sendMessage(string calldata data, string calldata destinationChain) public {
        emit MessageOut(msg.sender, data, destinationChain);
    }
}
