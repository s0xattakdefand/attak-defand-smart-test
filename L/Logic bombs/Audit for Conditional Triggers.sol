modifier notHardcodedAddress() {
    require(msg.sender != 0xAbc...123, "Suspicious caller");
    _;
}
