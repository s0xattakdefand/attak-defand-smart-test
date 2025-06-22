pragma solidity ^0.8.21;

interface IERC20 {
    function transferFrom(address, address, uint256) external returns (bool);
}

contract L2TokenTunnel {
    IERC20 public token;
    address public remoteL1Receiver;

    event TokenTunneled(address user, uint256 amount, string destination);

    constructor(address _token, address _l1Receiver) {
        token = IERC20(_token);
        remoteL1Receiver = _l1Receiver;
    }

    function tunnelTokens(uint256 amount, string memory destChain) external {
        token.transferFrom(msg.sender, address(this), amount);
        emit TokenTunneled(msg.sender, amount, destChain);
        // Off-chain relayer picks this up and forwards to L1
    }
}
