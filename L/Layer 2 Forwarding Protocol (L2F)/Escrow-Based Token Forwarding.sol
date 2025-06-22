pragma solidity ^0.8.21;

interface IERC20 {
    function transferFrom(address, address, uint256) external returns (bool);
}

contract L2TokenBridge {
    address public l1Receiver;
    IERC20 public token;

    event TokensForwarded(address indexed sender, uint256 amount);

    constructor(address _token, address _l1Receiver) {
        token = IERC20(_token);
        l1Receiver = _l1Receiver;
    }

    function forwardTokens(uint256 amount) external {
        token.transferFrom(msg.sender, address(this), amount);
        emit TokensForwarded(msg.sender, amount);
        // message sent off-chain to release on L1 (simulated)
    }
}
