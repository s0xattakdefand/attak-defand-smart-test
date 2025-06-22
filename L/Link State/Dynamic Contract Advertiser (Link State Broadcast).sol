pragma solidity ^0.8.21;

contract ModuleLinkAdvertiser {
    event LinkAlive(address indexed module, uint256 timestamp);
    event LinkDown(address indexed module);

    function ping() external {
        emit LinkAlive(msg.sender, block.timestamp);
    }

    function reportFailure(address module) external {
        emit LinkDown(module);
    }
}
