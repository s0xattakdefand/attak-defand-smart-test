// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

contract EncryptedMetadataVerifier {
    mapping(uint256 => bytes32) public encryptedMetadataHash;
    address public owner;

    event MetadataHashStored(uint256 indexed tokenId, bytes32 metadataHash);

    constructor() {
        owner = msg.sender;
    }

    modifier onlyOwner() {
        require(msg.sender == owner, "Not authorized");
        _;
    }

    /**
     * @notice Store the keccak256 hash of AES-encrypted metadata off-chain.
     * @param tokenId The tokenId of the NFT.
     * @param hash The keccak256 hash of the encrypted metadata.
     */
    function submitEncryptedHash(uint256 tokenId, bytes32 hash) public onlyOwner {
        encryptedMetadataHash[tokenId] = hash;
        emit MetadataHashStored(tokenId, hash);
    }

    /**
     * @notice View the stored hash for a token.
     */
    function getHash(uint256 tokenId) public view returns (bytes32) {
        return encryptedMetadataHash[tokenId];
    }
}
