struct AccessEvent {
    uint256 requestTime;
    uint256 blockTime;
    bool blocked;
    bool attacker;
}

mapping(address => AccessEvent[]) public logs;

function protectedCall() external {
    totalCalls++;

    AccessEvent memory log;
    log.requestTime = block.timestamp;
    log.attacker = isAttacker[msg.sender];

    if (isBlocked[msg.sender]) {
        blockedCalls++;
        log.blocked = true;
        log.blockTime = block.timestamp;

        if (log.attacker) {
            maliciousBlocked++;
        } else {
            falsePositives++;
        }

        logs[msg.sender].push(log);
        revert("Access denied");
    }

    logs[msg.sender].push(log); // record unblocked
}
