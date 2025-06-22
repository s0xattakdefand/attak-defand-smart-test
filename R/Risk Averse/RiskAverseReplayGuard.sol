contract RiskAverseReplayGuard {
    mapping(bytes32 => bool) public seen;

    modifier noReplay() {
        bytes32 hash = keccak256(msg.data);
        require(!seen[hash], "Replay attempt");
        seen[hash] = true;
        _;
    }
}
