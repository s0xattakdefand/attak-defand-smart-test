contract EOAIngressFilter {
    modifier onlyEOA() {
        require(msg.sender == tx.origin, "No contracts allowed");
        _;
    }

    function sensitiveAction() external onlyEOA {
        // Action only real users (not contracts) can perform
    }
}
