// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/// Attack Types: Checklist Skipping Attack, Fake Submission Attack, Replay Answer Attack
/// Defense Types: Sequential Enforcement, Signature/Hash Binding, Nonce/Session Binding

contract OpenChecklistInteractiveLanguage {
    address public admin;
    uint256 public checklistCount;
    mapping(uint256 => ChecklistItem) public checklist;
    mapping(address => uint256) public userProgress;
    mapping(bytes32 => bool) public usedSessions;

    struct ChecklistItem {
        string question;
        bytes32 expectedAnswerHash; // store the hash of the correct answer
    }

    event ChecklistItemCreated(uint256 indexed id, string question);
    event ChecklistCompleted(address indexed user);

    constructor() {
        admin = msg.sender;
    }

    modifier onlyAdmin() {
        require(msg.sender == admin, "Only admin");
        _;
    }

    // Admin defines checklist
    function createChecklistItem(string memory question, string memory expectedAnswer) external onlyAdmin {
        checklist[checklistCount] = ChecklistItem({
            question: question,
            expectedAnswerHash: keccak256(abi.encodePacked(expectedAnswer))
        });
        emit ChecklistItemCreated(checklistCount, question);
        checklistCount++;
    }

    // ATTACK Simulation: attacker fakes checklist completion without following order
    function attackFakeChecklistCompletion() external {
        userProgress[msg.sender] = checklistCount; // pretend all steps passed
        emit ChecklistCompleted(msg.sender);
    }

    // DEFENSE: Correct checklist progression
    function submitAnswer(
        string memory answer,
        uint256 sessionNonce,
        bytes32 sessionHash,
        uint8 v,
        bytes32 r,
        bytes32 s
    ) external {
        uint256 step = userProgress[msg.sender];
        require(step < checklistCount, "Checklist already completed");

        // enforce sequential order
        ChecklistItem memory item = checklist[step];
        require(keccak256(abi.encodePacked(answer)) == item.expectedAnswerHash, "Wrong answer");

        // prevent replay attacks
        require(!usedSessions[sessionHash], "Session already used");
        require(
            sessionHash == keccak256(abi.encodePacked(msg.sender, answer, sessionNonce)),
            "Invalid session hash"
        );

        address signer = ecrecover(toEthSignedMessageHash(sessionHash), v, r, s);
        require(signer == msg.sender, "Invalid signature");

        usedSessions[sessionHash] = true;

        // progress to next step
        userProgress[msg.sender]++;

        // if completed
        if (userProgress[msg.sender] == checklistCount) {
            emit ChecklistCompleted(msg.sender);
        }
    }

    // Utility function for Ethereum signed messages
    function toEthSignedMessageHash(bytes32 hash) internal pure returns (bytes32) {
        return keccak256(abi.encodePacked("\x19Ethereum Signed Message:\n32", hash));
    }

    // Helper to generate the session hash offchain
    function generateSessionHash(address user, string memory answer, uint256 nonce) external pure returns (bytes32) {
        return keccak256(abi.encodePacked(user, answer, nonce));
    }

    // View user's progress
    function viewProgress(address user) external view returns (uint256 currentStep, uint256 totalSteps) {
        return (userProgress[user], checklistCount);
    }
}
