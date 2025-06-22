contract FallbackRiskMonitor {
    event UnknownSelector(bytes4 selector, address origin);

    fallback() external {
        emit UnknownSelector(msg.sig, msg.sender);
    }
}
