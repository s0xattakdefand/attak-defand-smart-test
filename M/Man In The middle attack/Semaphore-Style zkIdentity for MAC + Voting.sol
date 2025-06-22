// SPDX-License-Identifier: MIT
pragma solidity ^0.8.21;

/// @title zkMACDAO - DAO with MAC rules & zkIdentity access control
contract zkMACDAO {
    mapping(bytes32 => bool) public allowedIdentities;
    address public coordinator;
    uint256 public proposalCount;

    struct Proposal {
        string description;
        uint256 voteCount;
    }

    mapping(uint256 => Proposal) public proposals;

    constructor(address _coordinator) {
        coordinator = _coordinator;
    }

    function registerIdentity(bytes32 zkId) external {
        require(msg.sender == coordinator, "Only coordinator");
        allowedIdentities[zkId] = true;
    }

    function propose(string calldata desc) external {
        proposals[++proposalCount] = Proposal(desc, 0);
    }

    function vote(uint256 proposalId, bytes32 zkIdProof) external {
        require(allowedIdentities[zkIdProof], "Not authorized by MAC");
        proposals[proposalId].voteCount += 1;
    }

    function result(uint256 id) external view returns (string memory, uint256) {
        Proposal memory p = proposals[id];
        return (p.description, p.voteCount);
    }
}
