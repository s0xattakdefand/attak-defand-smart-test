contract BroadcastEventBus {
    event Forwarded(address indexed source, string tag, string data);

    function forwardBroadcast(string calldata tag, string calldata data) public {
        emit Forwarded(msg.sender, tag, data);
    }
}
