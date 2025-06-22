// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/// AISSVerifier — Verifies device proofs or signatures from secure silicon implementations
contract AISSVerifier {
    address public admin;
    mapping(bytes32 => bool) public approvedDevices; // Device hash (e.g., keccak256(pubkey))

    event DeviceRegistered(bytes32 indexed deviceHash);
    event SecureProofAccepted(address indexed submitter, bytes32 deviceHash, bytes32 proofHash);

    modifier onlyAdmin() {
        require(msg.sender == admin, "Admin only");
        _;
    }

    constructor() {
        admin = msg.sender;
    }

    function registerDevice(bytes32 deviceHash) external onlyAdmin {
        approvedDevices[deviceHash] = true;
        emit DeviceRegistered(deviceHash);
    }

    function submitSecureProof(
        bytes32 deviceHash,
        bytes32 proofHash,
        bytes calldata signature
    ) external {
        require(approvedDevices[deviceHash], "Unrecognized device");
        bytes32 digest = keccak256(abi.encodePacked(deviceHash, proofHash, msg.sender));
        require(recoverSigner(digest, signature) == msg.sender, "Invalid signature");
        emit SecureProofAccepted(msg.sender, deviceHash, proofHash);
    }

    function recoverSigner(bytes32 hash, bytes calldata sig) internal pure returns (address) {
        require(sig.length == 65, "Invalid signature length");
        bytes32 r;
        bytes32 s;
        uint8 v;
        assembly {
            r := calldataload(sig.offset)
            s := calldataload(add(sig.offset, 32))
            v := byte(0, calldataload(add(sig.offset, 64)))
        }
        return ecrecover(hash, v, r, s);
    }
}
