contract SpamHub {
    event Routed(address sender, string msg);

    function sendSpam(string calldata message) external {
        for (uint i = 0; i < 100; i++) {
            emit Routed(msg.sender, message); // 🚨 Could overload listener / off-chain indexers
        }
    }
}
