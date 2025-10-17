pragma solidity ^0.8.0;

contract DXEAction {
    address public owner;
    mapping(string => uint256) public attackCounts;
    mapping(string => uint256) public defendCounts;
    mapping(string => bool) public wordExists;
    string[] public words;
    mapping(address => bool) public authorizedRewriters;
    mapping(string => bool) public initializedWords;

    struct Action {
        address user;
        string actionType;
        uint256 timestamp;
    }
    mapping(string => Action[]) public actionHistory;

    event WordSubmitted(address indexed user, string word);
    event AttackPerformed(address indexed user, string word, uint256 count);
    event DefendPerformed(address indexed user, string word, uint256 count);
    event WordRewritten(address indexed user, string word, uint256 newAttackCount, uint256 newDefendCount);
    event RewriterAuthorized(address indexed user);
    event RewriterRevoked(address indexed user);
    event ActionRecorded(address indexed user, string word, string actionType, uint256 timestamp);
    event WordInitialized(address indexed user, string word, uint256 initialAttackCount, uint256 initialDefendCount);

    modifier onlyOwner() {
        require(msg.sender == owner, "Only owner can call this function");
        _;
    }

    modifier onlyAuthorized() {
        require(msg.sender == owner || authorizedRewriters[msg.sender], "Not authorized to rewrite");
        _;
    }

    constructor() {
        owner = msg.sender;
        authorizedRewriters[msg.sender] = true;
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
        require(initializedWords[_word], "Word not initialized");
        attackCounts[_word]++;
        actionHistory[_word].push(Action(msg.sender, "attack", block.timestamp));
        emit AttackPerformed(msg.sender, _word, attackCounts[_word]);
        emit ActionRecorded(msg.sender, _word, "attack", block.timestamp);
    }

    function defend(string memory _word) public {
        require(wordExists[_word], "Word does not exist");
        require(initializedWords[_word], "Word not initialized");
        defendCounts[_word]++;
        actionHistory[_word].push(Action(msg.sender, "defend", block.timestamp));
        emit DefendPerformed(msg.sender, _word, defendCounts[_word]);
        emit ActionRecorded(msg.sender, _word, "defend", block.timestamp);
    }

    function rewriteWord(string memory _word, uint256 _newAttackCount, uint256 _newDefendCount) public onlyAuthorized {
        require(wordExists[_word], "Word does not exist");
        attackCounts[_word] = _newAttackCount;
        defendCounts[_word] = _newDefendCount;
        delete actionHistory[_word];
        initializedWords[_word] = true;
        emit WordRewritten(msg.sender, _word, _newAttackCount, _newDefendCount);
    }

    // DXE-inspired: Initialize a word with attack/defend counts
    function initializeWord(string memory _word, uint256 _initialAttackCount, uint256 _initialDefendCount) public onlyOwner {
        require(wordExists[_word], "Word does not exist");
        require(!initializedWords[_word], "Word already initialized");
        attackCounts[_word] = _initialAttackCount;
        defendCounts[_word] = _initialDefendCount;
        initializedWords[_word] = true;
        emit WordInitialized(msg.sender, _word, _initialAttackCount, _initialDefendCount);
    }

    function authorizeRewriter(address _user) public onlyOwner {
        require(_user != address(0), "Invalid address");
        authorizedRewriters[_user] = true;
        emit RewriterAuthorized(_user);
    }

    function revokeRewriter(address _user) public onlyOwner {
        require(_user != address(0), "Invalid address");
        authorizedRewriters[_user] = false;
        emit RewriterRevoked(_user);
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

    function isAuthorizedRewriter(address _user) public view returns (bool) {
        return authorizedRewriters[_user];
    }

    function getActionHistory(string memory _word) public view returns (Action[] memory) {
        require(wordExists[_word], "Word does not exist");
        return actionHistory[_word];
    }

    function isWordInitialized(string memory _word) public view returns (bool) {
        require(wordExists[_word], "Word does not exist");
        return initializedWords[_word];
    }

    function resetWord(string memory _word) public onlyOwner {
        require(wordExists[_word], "Word does not exist");
        attackCounts[_word] = 0;
        defendCounts[_word] = 0;
        delete actionHistory[_word];
        initializedWords[_word] = false;
    }
}