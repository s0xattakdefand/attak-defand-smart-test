contract FunctionTapMonitor {
    mapping(address => mapping(bytes4 => uint256)) public calls;

    modifier tap(bytes4 sel) {
        calls[msg.sender][sel]++;
        _;
    }

    function tappedFunction() external tap(msg.sig) returns (string memory) {
        return "Tapped and logged";
    }

    function callsFrom(address user, bytes4 sel) external view returns (uint256) {
        return calls[user][sel];
    }
}
