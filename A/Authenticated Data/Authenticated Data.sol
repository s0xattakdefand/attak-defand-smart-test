// SPDX-License-Identifier: MIT
pragma solidity ^0.8.25;

/// @title AuthenticatedDataManager - Secure verification of signed and zk-authenticated data

contract AuthenticatedDataManager {
    address public admin;

    mapping(bytes32 => bool) public usedDigests;

    event Authenticated(
        address indexed submitter,
        bytes32 indexed dataHash,
        string context,
        bytes4 selector,
        uint256 timestamp
    );

    modifier onlyAdmin() {
        require(msg.sender == admin, "Not authorized");
        _;
    }

    constructor() {
        admin = msg.sender;
    }

    /// @notice Submit signed data for verification
    function submitSignedData(bytes32 dataHash, bytes calldata signature, string calldata context) external {
        address signer = recoverSigner(dataHash, signature);
        require(signer != address(0), "Invalid signature");
        require(!usedDigests[dataHash], "Replay detected");

        usedDigests[dataHash] = true;
        emit Authenticated(signer, dataHash, context, msg.sig, block.timestamp);
    }

    /// @dev Recover signer from signature
    function recoverSigner(bytes32 hash, bytes memory sig) public pure returns (address) {
        require(sig.length == 65, "Invalid signature");
        bytes32 r; bytes32 s; uint8 v;
        assembly {
            r := mload(add(sig, 32))
            s := mload(add(sig, 64))
            v := byte(0, mload(add(sig, 96)))
        }
        return ecrecover(hash, v, r, s);
    }

    /// @notice Admin can store authenticated zk proof result
    function submitZKAuthenticatedData(bytes32 proofHash, string calldata context) external onlyAdmin {
        require(!usedDigests[proofHash], "Replay detected");
        usedDigests[proofHash] = true;
        emit Authenticated(msg.sender, proofHash, context, msg.sig, block.timestamp);
    }
}
