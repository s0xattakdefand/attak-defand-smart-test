// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/**
 * DEFENSE TYPE:
 * A commit-reveal scheme for short-lived secrets. 
 * You commit the hash of your secret, then reveal after some event. 
 * Attackers can't front-run or read the secret in the interim.
 */
contract EphemeralCommitReveal {
    struct CommitData {
        bytes32 commitHash;
        bool revealed;
    }

    mapping(address => CommitData) public commits;

    event Committed(address indexed user, bytes32 commitHash);
    event Revealed(address indexed user, string secret);

    function commitSecret(bytes32 commitHash) external {
        commits[msg.sender] = CommitData({
            commitHash: commitHash,
            revealed: false
        });
        emit Committed(msg.sender, commitHash);
    }

    function revealSecret(string calldata secret, bytes32 salt) external {
        CommitData storage c = commits[msg.sender];
        require(!c.revealed, "Already revealed");
        bytes32 check = keccak256(abi.encodePacked(secret, salt, msg.sender));
        require(check == c.commitHash, "Mismatch");
        c.revealed = true;
        emit Revealed(msg.sender, secret);
        // Secret is only visible in the event logs this once, not stored in a variable.
        // After the reveal, no indefinite storage of plaintext on-chain.
    }
}
