contract HoneymonkeyFallbackLogger {
    event UnknownCallReceived(address sender, uint256 value, bytes data);

    fallback() external payable {
        emit UnknownCallReceived(msg.sender, msg.value, msg.data);
    }

    receive() external payable {
        emit UnknownCallReceived(msg.sender, msg.value, "");
    }
}
