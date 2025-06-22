pragma solidity ^0.8.21;

contract RoleForwarder {
    mapping(address => bool) public allowedForwarders;
    address public target;

    event Forwarded(address from, bytes data);

    constructor(address _target) {
        target = _target;
        allowedForwarders[msg.sender] = true;
    }

    modifier onlyForwarder() {
        require(allowedForwarders[msg.sender], "Not allowed");
        _;
    }

    function updateForwarder(address fwd, bool allowed) external onlyForwarder {
        allowedForwarders[fwd] = allowed;
    }

    function forward(bytes calldata data) external onlyForwarder {
        (bool success, ) = target.call(data);
        require(success, "Forward failed");
        emit Forwarded(msg.sender, data);
    }
}
