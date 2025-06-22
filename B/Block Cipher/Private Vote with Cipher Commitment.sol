// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

contract PrivateVoteCipherCommitment {
    mapping(address => bytes32) public voteCommitment;
    mapping(address => bool) public hasVoted;

    event VoteCommitted(address indexed voter, bytes32 commitment);
    event VoteRevealed(address indexed voter, string vote);

    /**
     * @notice Commit a hashed vote using off-chain encryption (e.g., AES or hash).
     * @param commitment A hash of the encrypted vote or vote+salt (off-chain).
     */
    function commitVote(bytes32 commitment) public {
        require(!hasVoted[msg.sender], "Already committed");
        voteCommitment[msg.sender] = commitment;
        hasVoted[msg.sender] = true;

        emit VoteCommitted(msg.sender, commitment);
    }

    /**
     * @notice Reveal your original vote string and salt (optional).
     * This is only for demonstration and testing purposes.
     * In production, decryption would happen off-chain.
     * @param vote The original vote as string.
     * @param salt A random salt used during the hash commitment.
     */
    function revealVote(string memory vote, string memory salt) public view returns (bool matchSuccess) {
        bytes32 submitted = voteCommitment[msg.sender];
        bytes32 recomputed = keccak256(abi.encodePacked(vote, salt));

        return (submitted == recomputed);
    }

    function getMyCommitment() public view returns (bytes32) {
        return voteCommitment[msg.sender];
    }
}
