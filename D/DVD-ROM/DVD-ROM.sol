pragma solidity ^0.8.0;

contract WordAction {
    address public owner;
    mapping(string => uint256) public attackCounts;
    mapping(string => uint256) public defendCounts;
    string[] public words;
    mapping(string => bool) public wordExists;

    event WordSubmitted(address indexed user, string word);
    event AttackPerformed(address indexed user, string word, uint256 count);
    event DefendPerformed(address indexed user, string word, uint256 count);

    modifier onlyOwner() {
        require(msg.sender == owner, "Only owner can call this function");
        _;
    }

    constructor() {
        owner = msg.sender;
    }

    function submitWord(string memory _word) public {
        require(bytes(_word).length > 0, "Word cannot be empty");
        if (!wordExists[_word]) {
            words.push(_word);
            wordExists[_word] = true;
        }
        emit WordSubmitted(msg.sender, _word);
    }

    function attack(string memory _word) public {
        require(wordExists[_word], "Word does not exist");
        attackCounts[_word]++;
        emit AttackPerformed(msg.sender, _word, attackCounts[_word]);
    }

    function defend(string memory _word) public {
        require(wordExists[_word], "Word does not exist");
        defendCounts[_word]++;
        emit DefendPerformed(msg.sender, _word, defendCounts[_word]);
    }

    function getWordCount() public view returns (uint256) {
        return words.length;
    }

    function getAttackCount(string memory _word) public view returns (uint256) {
        require(wordExists[_word], "Word does not exist");
        return attackCounts[_word];
    }

    function getDefendCount(string memory _word) public view returns (uint256) {
        require(wordExists[_word], "Word does not exist");
        return defendCounts[_word];
    }

    function getAllWords() public view returns (string[] memory) {
        return words;
    }

    function resetWord(string memory _word) public onlyOwner {
        require(wordExists[_word], "Word does not exist");
        attackCounts[_word] = 0;
        defendCounts[_word] = 0;
    }
}