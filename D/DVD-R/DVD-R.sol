pragma solidity ^0.8.0;

contract DVDRGame {
    bytes32 private constant SECRET_WORD_HASH = keccak256(abi.encodePacked("DVD-R"));
    uint256 public attackCount;
    uint256 public defenseCount;
    
    event AttackExecuted(address indexed player, uint256 timestamp);
    event DefendExecuted(address indexed player, uint256 timestamp);
    event InvalidWord(address indexed player, string message);

    modifier validWord(string memory word) {
        require(keccak256(abi.encodePacked(word)) == SECRET_WORD_HASH, "Incorrect word");
        _;
    }

    function attack(string memory word) external validWord(word) {
        attackCount++;
        emit AttackExecuted(msg.sender, block.timestamp);
    }

    function defend(string memory word) external validWord(word) {
        defenseCount++;
        emit DefendExecuted(msg.sender, block.timestamp);
    }

    function getCounts() external view returns (uint256 attacks, uint256 defenses) {
        return (attackCount, defenseCount);
    }
}