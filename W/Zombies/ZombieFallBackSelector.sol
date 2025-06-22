contract ZombieFallbackSelector {
    event Drifted(bytes4 selector);

    fallback() external {
        emit Drifted(msg.sig); // unknown selector detected
    }
}
