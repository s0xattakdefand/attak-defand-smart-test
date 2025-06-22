pragma solidity ^0.8.24;

contract MockZKIdentityVerifier {
    mapping(address => bool) public verifiedIdentities;

    function verifyIdentity(address voter, bytes memory) external view returns (bool) {
        return verifiedIdentities[voter];
    }

    function setIdentity(address voter, bool verified) external {
        verifiedIdentities[voter] = verified;
    }
}
