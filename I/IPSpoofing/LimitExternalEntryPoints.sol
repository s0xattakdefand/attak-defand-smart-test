contract Gatekeeper {
    modifier onlyEOA() {
        require(msg.sender == tx.origin, "No contracts allowed");
        _;
    }

    function openGate() external onlyEOA {
        // prevent contract-based spoofing
    }
}
