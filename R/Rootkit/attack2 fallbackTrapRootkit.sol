contract FallbackRootkit {
    fallback() external payable {
        if (msg.sig == 0xdeadbeef) {
            // execute hidden command
        }
    }
}
