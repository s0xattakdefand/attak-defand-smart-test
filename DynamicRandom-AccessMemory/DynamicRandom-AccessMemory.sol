// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

contract DRAMAction {
    address public owner;
    mapping(string => uint256) public attackCounts;
    mapping(string => uint256) public defendCounts;
    mapping(string => bool) public wordExists;
    string[] public words;
    mapping(string => bool) public initializedWords;
    mapping(string => string) public wordMetadata;

    enum Role { None, Attacker, Defender, Rewriter, Scanner, Measurer, Refresher }
    mapping(string => mapping(address => Role)) public userRoles;

    struct Action {
        address user;
        string actionType;
        uint256 timestamp;
    }
    mapping(string => Action[]) public actionHistory;

    struct Vulnerability {
        string issue;
        uint256 timestamp;
        uint256 attackCount;
        uint256 defendCount;
    }
    mapping(string => Vulnerability[]) public vulnerabilities;

    struct TrustMeasurement {
        bool isTrusted;
        string measurement;
        uint256 timestamp;
        uint256 attackCount;
        uint256 defendCount;
    }
    mapping(string => TrustMeasurement[]) public trustMeasurements;

    event WordSubmitted(address indexed user, string word);
    event AttackPerformed(address indexed user, string word, uint256 count);
    event DefendPerformed(address indexed user, string word, uint256 count);
    event WordRewritten(address indexed user, string word, uint256 newAttackCount, uint256 newDefendCount);
    event WordInitialized(address indexed user, string word, uint256 initialAttackCount, uint256 initialDefendCount);
    event RoleAssigned(address indexed user, string word, Role role);
    event RoleRevoked(address indexed user, string word);
    event ActionRecorded(address indexed user, string word, string actionType, uint256 timestamp);
    event VulnerabilityDetected(address indexed user, string word, string issue, uint256 attackCount, uint256 defendCount);
    event TrustMeasured(address indexed user, string word, bool isTrusted, string measurement, uint256 attackCount, uint256 defendCount);
    event MemoryRefreshed(address indexed user, string word, string newMetadata);

    modifier onlyOwner() {
        require(msg.sender == owner, "Only owner");
        _;
    }

    modifier onlyAuthorizedForWord(string memory _word, Role _requiredRole) {
        require(wordExists[_word], "Word does not exist");
        require(userRoles[_word][msg.sender] == _requiredRole || msg.sender == owner, "Not authorized");
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

    function attack(string memory _word) public onlyAuthorizedForWord(_word, Role.Attacker) {
        require(initializedWords[_word], "Word not initialized");
        attackCounts[_word]++;
        actionHistory[_word].push(Action(msg.sender, "attack", block.timestamp));
        emit AttackPerformed(msg.sender, _word, attackCounts[_word]);
        emit ActionRecorded(msg.sender, _word, "attack", block.timestamp);
    }

    function defend(string memory _word) public onlyAuthorizedForWord(_word, Role.Defender) {
        require(initializedWords[_word], "Word not initialized");
        defendCounts[_word]++;
        actionHistory[_word].push(Action(msg.sender, "defend", block.timestamp));
        emit DefendPerformed(msg.sender, _word, defendCounts[_word]);
        emit ActionRecorded(msg.sender, _word, "defend", block.timestamp);
    }

    function rewriteWord(string memory _word, uint256 _newAttackCount, uint256 _newDefendCount) public onlyAuthorizedForWord(_word, Role.Rewriter) {
        require(initializedWords[_word], "Word not initialized");
        attackCounts[_word] = _newAttackCount;
        defendCounts[_word] = _newDefendCount;
        delete actionHistory[_word];
        delete vulnerabilities[_word];
        delete trustMeasurements[_word];
        emit WordRewritten(msg.sender, _word, _newAttackCount, _newDefendCount);
    }

    function initializeWord(string memory _word, uint256 _initialAttackCount, uint256 _initialDefendCount, string memory _initialMetadata) public onlyOwner {
        require(wordExists[_word], "Word does not exist");
        require(!initializedWords[_word], "Word already initialized");
        attackCounts[_word] = _initialAttackCount;
        defendCounts[_word] = _initialDefendCount;
        wordMetadata[_word] = _initialMetadata;
        initializedWords[_word] = true;
        emit WordInitialized(msg.sender, _word, _initialAttackCount, _initialDefendCount);
        emit MemoryRefreshed(msg.sender, _word, _initialMetadata);
    }

    function assignRole(address _user, string memory _word, Role _role) public onlyOwner {
        require(wordExists[_word], "Word does not exist");
        require(_user != address(0), "Invalid address");
        userRoles[_word][_user] = _role;
        emit RoleAssigned(_user, _word, _role);
    }

    function revokeRole(address _user, string memory _word) public onlyOwner {
        require(wordExists[_word], "Word does not exist");
        require(_user != address(0), "Invalid address");
        userRoles[_word][_user] = Role.None;
        emit RoleRevoked(_user, _word);
    }

    function scanForVulnerabilities(string memory _word) public onlyAuthorizedForWord(_word, Role.Scanner) {
        require(initializedWords[_word], "Word not initialized");
        uint256 attackCount = attackCounts[_word];
        uint256 defendCount = defendCounts[_word];
        string memory issue;

        if (attackCount > defendCount * 2) {
            issue = "High attack count";
            vulnerabilities[_word].push(Vulnerability(issue, block.timestamp, attackCount, defendCount));
            emit VulnerabilityDetected(msg.sender, _word, issue, attackCount, defendCount);
        } else if (defendCount > attackCount * 2) {
            issue = "High defend count";
            vulnerabilities[_word].push(Vulnerability(issue, block.timestamp, attackCount, defendCount));
            emit VulnerabilityDetected(msg.sender, _word, issue, attackCount, defendCount);
        } else if (attackCount + defendCount > 100) {
            issue = "Excessive actions";
            vulnerabilities[_word].push(Vulnerability(issue, block.timestamp, attackCount, defendCount));
            emit VulnerabilityDetected(msg.sender, _word, issue, attackCount, defendCount);
        }
    }

    function measureTrust(string memory _word) public onlyAuthorizedForWord(_word, Role.Measurer) {
        require(initializedWords[_word], "Word not initialized");
        uint256 attackCount = attackCounts[_word];
        uint256 defendCount = defendCounts[_word];
        bool isTrusted;
        string memory measurement;

        if (attackCount >= defendCount + 10) {
            isTrusted = false;
            measurement = "Untrusted: Excessive attacks";
        } else if (defendCount >= attackCount * 2 && attackCount + defendCount > 20) {
            isTrusted = true;
            measurement = "Trusted: Strong defense";
        } else if (attackCount + defendCount < 10) {
            isTrusted = true;
            measurement = "Trusted: Low activity";
        } else {
            isTrusted = false;
            measurement = "Untrusted: Suspicious pattern";
        }

        trustMeasurements[_word].push(TrustMeasurement(isTrusted, measurement, block.timestamp, attackCount, defendCount));
        emit TrustMeasured(msg.sender, _word, isTrusted, measurement, attackCount, defendCount);
    }

    function refreshMemory(string memory _word, string memory _newMetadata) public onlyAuthorizedForWord(_word, Role.Refresher) {
        require(initializedWords[_word], "Word not initialized");
        require(bytes(_newMetadata).length > 0, "Metadata cannot be empty");
        wordMetadata[_word] = _newMetadata;
        emit MemoryRefreshed(msg.sender, _word, _newMetadata);
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

    function getMetadata(string memory _word) public view returns (string memory) {
        require(wordExists[_word], "Word does not exist");
        return wordMetadata[_word];
    }

    function getAllWords() public view returns (string[] memory) {
        return words;
    }

    function getActionHistory(string memory _word) public view returns (Action[] memory) {
        require(wordExists[_word], "Word does not exist");
        return actionHistory[_word];
    }

    function getVulnerabilities(string memory _word) public view returns (Vulnerability[] memory) {
        require(wordExists[_word], "Word does not exist");
        return vulnerabilities[_word];
    }

    function getTrustMeasurements(string memory _word) public view returns (TrustMeasurement[] memory) {
        require(wordExists[_word], "Word does not exist");
        return trustMeasurements[_word];
    }

    function isWordInitialized(string memory _word) public view returns (bool) {
        require(wordExists[_word], "Word does not exist");
        return initializedWords[_word];
    }

    function getUserRole(address _user, string memory _word) public view returns (Role) {
        require(wordExists[_word], "Word does not exist");
        return userRoles[_word][_user];
    }

    function resetWord(string memory _word) public onlyOwner {
        require(wordExists[_word], "Word does not exist");
        attackCounts[_word] = 0;
        defendCounts[_word] = 0;
        delete actionHistory[_word];
        delete vulnerabilities[_word];
        delete trustMeasurements[_word];
        delete wordMetadata[_word];
        initializedWords[_word] = false;
        emit WordRewritten(msg.sender, _word, 0, 0);
    }
}