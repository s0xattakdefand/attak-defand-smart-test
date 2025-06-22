pragma solidity ^0.8.21;

contract QuantumSafeDAO {
    mapping(bytes32 => bool) public validWalletHashes; // hash(latticePublicKey)
    mapping(bytes32 => bool) public hasVoted;
    uint256 public totalVotes;

    function registerWallet(bytes32 walletHash) external {
        validWalletHashes[walletHash] = true;
    }

    function vote(bytes32 walletHash) external {
        require(validWalletHashes[walletHash], "Not quantum-safe verified");
        require(!hasVoted[walletHash], "Already voted");
        hasVoted[walletHash] = true;
        totalVotes++;
    }
}
