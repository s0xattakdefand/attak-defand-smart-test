contract UniversalBroadcast {
    event Broadcast(string indexed tag, string message);

    function broadcast(string calldata tag, string calldata message) public {
        emit Broadcast(tag, message);
    }
}
