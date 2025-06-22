contract ReentryExposureMonitor {
    mapping(address => uint8) public attempts;
    bool private locked;

    event ReentryDetected(address indexed origin, uint8 count);

    modifier noReentry() {
        require(!locked, "Reentry blocked");
        locked = true;
        _;
        locked = false;
    }

    function critical() external noReentry {
        attempts[tx.origin]++;
        emit ReentryDetected(tx.origin, attempts[tx.origin]);
    }
}
