// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

contract CorrectReIdentification {
    address public admin;

    struct IdentityRecord {
        bytes32 identityHash;   // hashed(realID + nonce)
        bool revealed;
        string realId;          // revealed string (once)
    }

    mapping(address => IdentityRecord) public records;

    event IdentityRegistered(address indexed user, bytes32 identityHash);
    event IdentityRevealed(address indexed user, string realId);

    modifier onlyAdmin() {
        require(msg.sender == admin, "Only admin");
        _;
    }

    constructor() {
        admin = msg.sender;
    }

    // User pseudonym registration (only hash stored)
    function registerIdentity(bytes32 identityHash) external {
        require(records[msg.sender].identityHash == 0, "Already registered");
        records[msg.sender] = IdentityRecord(identityHash, false, "");
        emit IdentityRegistered(msg.sender, identityHash);
    }

    // Admin reveals identity upon authorized condition (e.g., court order or DAO vote)
    function revealIdentity(address user, string calldata realId, string calldata nonce) external onlyAdmin {
        IdentityRecord storage rec = records[user];
        require(!rec.revealed, "Already revealed");

        // Check hash integrity
        require(
            keccak256(abi.encodePacked(realId, nonce)) == rec.identityHash,
            "Hash mismatch"
        );

        rec.realId = realId;
        rec.revealed = true;
        emit IdentityRevealed(user, realId);
    }

    // View anonymized state
    function getIdentityStatus(address user) external view returns (
        bytes32 identityHash,
        bool revealed,
        string memory realId
    ) {
        IdentityRecord memory rec = records[user];
        return (rec.identityHash, rec.revealed, rec.revealed ? rec.realId : "");
    }
}
