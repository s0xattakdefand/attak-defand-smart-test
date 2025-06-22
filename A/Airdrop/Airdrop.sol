// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "@openzeppelin/contracts/utils/cryptography/MerkleProof.sol";
import "@openzeppelin/contracts/token/ERC20/IERC20.sol";

contract MerkleAirdrop {
    address public admin;
    IERC20 public token;
    bytes32 public merkleRoot;
    mapping(address => bool) public claimed;

    event AirdropClaimed(address indexed user, uint256 amount);

    constructor(address tokenAddress, bytes32 root) {
        admin = msg.sender;
        token = IERC20(tokenAddress);
        merkleRoot = root;
    }

    function claim(uint256 amount, bytes32[] calldata proof) external {
        require(!claimed[msg.sender], "Already claimed");
        bytes32 leaf = keccak256(abi.encodePacked(msg.sender, amount));
        require(MerkleProof.verify(proof, merkleRoot, leaf), "Invalid proof");

        claimed[msg.sender] = true;
        require(token.transfer(msg.sender, amount), "Transfer failed");

        emit AirdropClaimed(msg.sender, amount);
    }

    function updateMerkleRoot(bytes32 newRoot) external {
        require(msg.sender == admin, "Not admin");
        merkleRoot = newRoot;
    }
}
