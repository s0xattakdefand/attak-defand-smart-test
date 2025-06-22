// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

contract CommitmentCover {
    struct Commitment {
        bytes32 hash;
        uint256 committedAt;
        bool revealed;
    }

    mapping(address => Commitment) public commitments;

    event Committed(address indexed user, bytes32 commitmentHash);
    event Revealed(address indexed user, bytes32 secret, uint256 timestamp);

    function commit(bytes32 commitmentHash) external {
        require(commitments[msg.sender].committedAt == 0, "Already committed");
        commitments[msg.sender] = Commitment(commitmentHash, block.timestamp, false);
        emit Committed(msg.sender, commitmentHash);
    }

    function reveal(bytes32 secret) external {
        Commitment storage c = commitments[msg.sender];
        require(!c.revealed, "Already revealed");
        require(c.hash == keccak256(abi.encodePacked(secret)), "Invalid reveal");

        c.revealed = true;
        emit Revealed(msg.sender, secret, block.timestamp);
        // Act on the revealed secret (e.g., vote, mint, etc.)
    }

    function isRevealed(address user) external view returns (bool) {
        return commitments[user].revealed;
    }
}
