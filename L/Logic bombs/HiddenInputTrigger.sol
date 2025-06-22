// SPDX-License-Identifier: MIT
pragma solidity ^0.8.21;

contract ArithmeticLogicBomb {
    uint256 public constant TRIGGER = 1337 * 42;

    function execute(uint256 input) external {
        if (input == TRIGGER) {
            selfdestruct(payable(msg.sender)); // 💣 Selfdestruct only on exact input
        }
    }

    function safeLogic() external pure returns (string memory) {
        return "Harmless looking function";
    }
}
