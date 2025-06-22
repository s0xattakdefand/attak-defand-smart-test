pragma solidity ^0.8.21;

contract L2Forwarder {
    address public trustedRelayer;

    event Forwarded(address indexed to, bytes data);

    constructor(address _relayer) {
        trustedRelayer = _relayer;
    }

    modifier onlyRelayer() {
        require(msg.sender == trustedRelayer, "Not authorized");
        _;
    }

    function forward(address target, bytes calldata data) external onlyRelayer {
        (bool success, ) = target.call(data);
        require(success, "Forward failed");
        emit Forwarded(target, data);
    }
}
