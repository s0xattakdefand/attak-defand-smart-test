contract OriginGuard {
    modifier noOriginSpoof() {
        require(tx.origin == msg.sender, "Origin mismatch");
        _;
    }

    function secureRootOnly() external noOriginSpoof {
        // only local call allowed
    }
}
