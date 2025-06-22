// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/// AES Algorithm Validation Suite (AES-AVS)
contract AESValidator {
    struct AESCase {
        bytes32 ciphertextCommitment;
        bool validated;
        uint256 validatedAt;
        string plaintext;
    }

    address public admin;
    mapping(address => AESCase[]) public validations;

    event AESCaseSubmitted(address indexed user, bytes32 commitment);
    event AESCaseValidated(address indexed user, uint256 caseId, string plaintext);

    modifier onlyAdmin() {
        require(msg.sender == admin, "Not admin");
        _;
    }

    constructor() {
        admin = msg.sender;
    }

    /// Submit new AES test case (offchain encrypted and hashed)
    function submitCase(bytes32 ciphertextCommitment) external {
        validations[msg.sender].push(AESCase(ciphertextCommitment, false, 0, ""));
        emit AESCaseSubmitted(msg.sender, ciphertextCommitment);
    }

    /// Validate AES decryption: hash(decryptedText, keyHash) must match commitment
    function validateCase(uint256 caseId, string calldata decryptedText, bytes32 keyHash) external {
        AESCase storage aesCase = validations[msg.sender][caseId];
        require(!aesCase.validated, "Already validated");

        bytes32 check = keccak256(abi.encodePacked(decryptedText, keyHash));
        require(check == aesCase.ciphertextCommitment, "Invalid AES decryption");

        aesCase.validated = true;
        aesCase.validatedAt = block.timestamp;
        aesCase.plaintext = decryptedText;

        emit AESCaseValidated(msg.sender, caseId, decryptedText);
    }

    function getCase(address user, uint256 index) external view returns (AESCase memory) {
        return validations[user][index];
    }
}
