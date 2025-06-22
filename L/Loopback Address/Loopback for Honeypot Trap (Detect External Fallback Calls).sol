pragma solidity ^0.8.21;

contract LoopbackTrap {
    event Triggered(address caller, uint256 gasLeft);

    fallback() external payable {
        require(msg.sender != address(this), "Loopback call detected");
        emit Triggered(msg.sender, gasleft());
    }

    function trigger() external {
        // fake vulnerable call
        address(this).call(abi.encodeWithSignature("fake()"));
    }
}
