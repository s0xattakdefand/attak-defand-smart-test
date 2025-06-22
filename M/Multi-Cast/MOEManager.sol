struct ReceiverStats {
    uint256 received;
    uint256 success;
    uint256 failed;
}

mapping(address => ReceiverStats) public receiverMOE;

function logMulticastResult(address target, bool ok) external {
    ReceiverStats storage stats = receiverMOE[target];
    stats.received++;
    if (ok) {
        stats.success++;
    } else {
        stats.failed++;
    }
}

function getReceiverStats(address target) external view returns (uint256 r, uint256 s, uint256 f) {
    ReceiverStats storage stats = receiverMOE[target];
    return (stats.received, stats.success, stats.failed);
}
