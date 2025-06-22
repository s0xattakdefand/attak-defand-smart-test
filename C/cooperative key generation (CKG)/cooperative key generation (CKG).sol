// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

contract CKGManager {
    struct KeyShare {
        bytes32 commitment;   // Hash(commitment)
        bytes share;          // Later revealed
        bool revealed;
    }

    mapping(address => KeyShare) public keyShares;
    address[] public participants;

    event CommitmentSubmitted(address indexed user, bytes32 commitment);
    event ShareRevealed(address indexed user, bytes share);
    event CooperativeKeyFinalized(bytes32 groupKeyHash);

    modifier onlyParticipant() {
        require(keyShares[msg.sender].commitment != bytes32(0), "Not registered");
        _;
    }

    function register(bytes32 commitment) external {
        require(keyShares[msg.sender].commitment == bytes32(0), "Already registered");
        keyShares[msg.sender].commitment = commitment;
        participants.push(msg.sender);
        emit CommitmentSubmitted(msg.sender, commitment);
    }

    function reveal(bytes calldata share) external onlyParticipant {
        require(!keyShares[msg.sender].revealed, "Already revealed");
        require(keccak256(share) == keyShares[msg.sender].commitment, "Invalid share");
        keyShares[msg.sender].share = share;
        keyShares[msg.sender].revealed = true;
        emit ShareRevealed(msg.sender, share);
    }

    function finalizeKey() external view returns (bytes32 groupKeyHash) {
        bytes memory allShares;
        for (uint256 i = 0; i < participants.length; i++) {
            require(keyShares[participants[i]].revealed, "Unrevealed share");
            allShares = abi.encodePacked(allShares, keyShares[participants[i]].share);
        }
        return keccak256(allShares); // Simulated group key hash
    }
}
