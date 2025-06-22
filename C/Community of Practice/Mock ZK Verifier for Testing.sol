pragma solidity ^0.8.24;

contract MockZKIdentityVerifier {
    mapping(address => bool) public identities;

    function verify(address user, bytes memory) external view returns (bool) {
        return identities[user];
    }

    function setIdentity(address user, bool verified) external {
        identities[user] = verified;
    }
}
