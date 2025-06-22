// SPDX-License-Identifier: MIT
pragma solidity ^0.8.21;

/// @title Zombie - Dormant Contract Reanimator (CREATE2 friendly)
contract Zombie {
    address public owner;
    bool public active;
    bytes4 public reactivationSelector;

    event Received(address from, uint256 amount);
    event Reactivated(address executor, bytes4 selector);
    event Executed(bytes4 selector, bool success);
    event Destroyed(address collector);

    constructor(bytes4 _selector) payable {
        owner = msg.sender;
        reactivationSelector = _selector;
        active = false;
    }

    modifier onlyOwner() {
        require(msg.sender == owner, "Not owner");
        _;
    }

    /// @notice Reactivate zombie with correct selector
    fallback() external payable {
        if (msg.sig == reactivationSelector && !active) {
            active = true;
            emit Reactivated(msg.sender, msg.sig);
        } else if (active) {
            (bool ok, ) = address(this).delegatecall(msg.data);
            emit Executed(msg.sig, ok);
        }
    }

    receive() external payable {
        emit Received(msg.sender, msg.value);
    }

    function kill(address payable to) external onlyOwner {
        emit Destroyed(to);
        selfdestruct(to);
    }
}
