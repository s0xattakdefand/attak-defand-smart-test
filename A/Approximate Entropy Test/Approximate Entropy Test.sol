// SPDX-License-Identifier: MIT
pragma solidity ^0.8.25;

interface IZKVerifier {
    function verifyProof(bytes calldata proof, bytes32 signal) external view returns (bool);
}

contract ApprovedSecurityFunctions {
    address public admin;
    mapping(address => bool) public trustedSigners;
    mapping(address => bool) public verifiedZKUsers;
    mapping(bytes32 => bool) public commitments;

    event Commit(bytes32 indexed hash, address indexed user);
    event VerifiedSignature(address indexed user);
    event ZKValidated(address indexed user, bytes32 signal);

    constructor() {
        admin = msg.sender;
    }

    modifier onlyAdmin() {
        require(msg.sender == admin, "Not admin");
        _;
    }

    // --- ASF #1: Hash Commitment (keccak256) ---
    function commit(bytes32 hash) external {
        commitments[hash] = true;
        emit Commit(hash, msg.sender);
    }

    function validateReveal(uint256 val, string calldata salt) external view returns (bool) {
        return commitments[keccak256(abi.encodePacked(val, salt))];
    }

    // --- ASF #2: Signature Verification (ecrecover) ---
    function verifySignature(bytes32 hash, bytes calldata sig) external returns (bool) {
        address signer = _recover(hash, sig);
        require(trustedSigners[signer], "Untrusted signer");
        emit VerifiedSignature(signer);
        return true;
    }

    function _recover(bytes32 hash, bytes memory sig) internal pure returns (address) {
        bytes32 ethHash = keccak256(abi.encodePacked("\x19Ethereum Signed Message:\n32", hash));
        (bytes32 r, bytes32 s, uint8 v) = _split(sig);
        return ecrecover(ethHash, v, r, s);
    }

    function _split(bytes memory sig) internal pure returns (bytes32 r, bytes32 s, uint8 v) {
        require(sig.length == 65, "Bad sig");
        assembly {
            r := mload(add(sig, 32))
            s := mload(add(sig, 64))
            v := byte(0, mload(add(sig, 96)))
        }
    }

    function addTrustedSigner(address signer) external onlyAdmin {
        trustedSigners[signer] = true;
    }

    // --- ASF #3: zkProof Stub ---
    function zkValidate(IZKVerifier verifier, bytes calldata proof, bytes32 signal) external {
        require(verifier.verifyProof(proof, signal), "ZK validation failed");
        verifiedZKUsers[msg.sender] = true;
        emit ZKValidated(msg.sender, signal);
    }

    function isZKUser(address user) external view returns (bool) {
        return verifiedZKUsers[user];
    }
}
