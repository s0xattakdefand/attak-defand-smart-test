// SPDX-License-Identifier: MIT
pragma solidity ^0.8.21;

/// @title LoopbackVerifier - Internal-only execution enforcement
contract LoopbackVerifier {
    event InternalOnlyLogicExecuted(address by);

    modifier onlySelf() {
        require(msg.sender == address(this), "Only internal call");
        _;
    }

    function startLoopbackAction() external {
        this.internalOnlyLogic(); // 👈 triggers modifier check
    }

    function internalOnlyLogic() external onlySelf {
        emit InternalOnlyLogicExecuted(msg.sender);
    }
}
