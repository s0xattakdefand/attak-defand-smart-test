contract AutoIncidentMonitor {
    uint256 public lastGas;
    bool public alert;

    function sensitiveCall() external {
        lastGas = gasleft();
        if (lastGas < 100000) {
            alert = true; // 🚨 auto incident trigger
        }
    }
}
