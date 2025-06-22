// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "./EAPAuthenticator.sol";

contract CommitRevealEAPMethod is IEAPMethod {
    // For demonstration, commitments are stored in this contract.
    // In a real setting, commitments might be set through a separate process.
    mapping(address => bytes32) public commitments;

    event CommitmentSet(address indexed user, bytes32 commitment);

    /**
     * @notice User calls this function off-chain to commit their secret.
     */
    function setCommitment(bytes32 commit) external {
        commitments[msg.sender] = commit;
        emit CommitmentSet(msg.sender, commit);
    }
    
    /**
     * @notice For EAP verification, the user provides a proof containing the secret and salt.
     * The contract checks if keccak256(secret, salt, user) matches the stored commitment.
     */
    function verify(address user, bytes calldata proof) external view override returns (bool) {
        // Expect proof = abi.encode(secret, salt) where secret is a string and salt is bytes32
        (string memory secret, bytes32 salt) = abi.decode(proof, (string, bytes32));
        bytes32 check = keccak256(abi.encodePacked(secret, salt, user));
        return (check == commitments[user]);
    }
}
