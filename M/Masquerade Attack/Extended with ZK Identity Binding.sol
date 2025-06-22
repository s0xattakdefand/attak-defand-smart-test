// SPDX-License-Identifier: MIT
pragma solidity ^0.8.21;

import "../zkMetaTx/zkSemaphoreRegistry.sol";

contract zkMACDAO {
    zkSemaphoreRegistry public identityRegistry;
    address public root;
    uint256 public proposalCount;

    struct Proposal {
        string description;
        uint256 votes;
    }

    mapping(uint256 => Proposal) public proposals;

    constructor(address _registry) {
        identityRegistry = zkSemaphoreRegistry(_registry);
        root = msg.sender;
    }

    function propose(string calldata desc) external {
        proposals[++proposalCount] = Proposal(desc, 0);
    }

    function vote(uint256 id, bytes32 zkId) external {
        require(identityRegistry.isValid(zkId), "Unverified ZK identity");
        proposals[id].votes += 1;
    }

    function result(uint256 id) external view returns (string memory, uint256) {
        return (proposals[id].description, proposals[id].votes);
    }
}
