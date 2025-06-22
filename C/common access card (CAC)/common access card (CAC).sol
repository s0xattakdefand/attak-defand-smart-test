// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

contract CommonAccessCardRegistry {
    address public admin;

    struct CACRecord {
        bytes32 identityHash;  // keccak256("name:rank:clearance") or similar
        bool active;
    }

    mapping(address => CACRecord) public cacIdentities;
    mapping(address => uint256) public nonces;

    event CACRegistered(address indexed user, bytes32 identityHash);
    event CACRevoked(address indexed user);

    modifier onlyAdmin() {
        require(msg.sender == admin, "Not admin");
        _;
    }

    constructor() {
        admin = msg.sender;
    }

    function registerCAC(address user, bytes32 identityHash) external onlyAdmin {
        require(!cacIdentities[user].active, "Already registered");
        cacIdentities[user] = CACRecord(identityHash, true);
        emit CACRegistered(user, identityHash);
    }

    function revokeCAC(address user) external onlyAdmin {
        require(cacIdentities[user].active, "Not active");
        cacIdentities[user].active = false;
        emit CACRevoked(user);
    }

    // On-chain CAC signature verification (EIP-191 / EIP-712 style)
    function verifyCACAccess(
        address user,
        string calldata resource,
        uint256 nonce,
        bytes calldata signature
    ) external view returns (bool) {
        require(cacIdentities[user].active, "Inactive CAC");
        require(nonce == nonces[user], "Invalid nonce");

        bytes32 messageHash = keccak256(abi.encodePacked(user, resource, nonce));
        bytes32 ethSigned = keccak256(abi.encodePacked("\x19Ethereum Signed Message:\n32", messageHash));

        return recoverSigner(ethSigned, signature) == user;
    }

    function useCACNonce(address user) external onlyAdmin {
        nonces[user]++;
    }

    function recoverSigner(bytes32 hash, bytes memory sig) internal pure returns (address) {
        require(sig.length == 65, "Invalid sig length");
        bytes32 r; bytes32 s; uint8 v;
        assembly {
            r := mload(add(sig, 32))
            s := mload(add(sig, 64))
            v := byte(0, mload(add(sig, 96)))
        }
        return ecrecover(hash, v, r, s);
    }

    function getCAC(address user) external view returns (bytes32, bool, uint256) {
        CACRecord memory rec = cacIdentities[user];
        return (rec.identityHash, rec.active, nonces[user]);
    }
}
