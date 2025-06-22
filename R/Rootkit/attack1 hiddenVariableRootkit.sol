contract HiddenVarRootkit {
    // Slot 5 is untracked but holds power
    uint256 private dummy1; // slot 0
    uint256 private dummy2; // slot 1
    // ...
    uint256 private maliciousPower; // slot 5

    function setPower(uint256 level) external {
        assembly { sstore(5, level) } // hide in raw slot
    }

    function executeIfLevel(uint256 threshold) external {
        require(getPower() >= threshold, "Insufficient rootkit power");
        // execute hidden logic
    }

    function getPower() public view returns (uint256 val) {
        assembly { val := sload(5) }
    }
}
