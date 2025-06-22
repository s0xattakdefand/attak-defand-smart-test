// SPDX-License-Identifier: MIT
pragma solidity ^0.8.25;

/// @title ATMCellRelay - Simulates fixed-size ATM-like packet relay in Solidity

contract ATMCellRelay {
    struct ATMCell {
        address sender;
        uint8 qos;                  // Quality of Service tag
        bytes32 payloadHash;
        uint64 timestamp;
        uint64 nonce;
    }

    mapping(bytes32 => bool) public usedCells;

    event CellProcessed(address indexed sender, uint8 qos, bytes32 payloadHash);

    uint256 public constant MAX_LATENCY = 5 minutes;

    function relayCell(
        address sender,
        uint8 qos,
        bytes32 payloadHash,
        uint64 timestamp,
        uint64 nonce,
        bytes calldata signature
    ) external {
        require(block.timestamp >= timestamp, "future cell");
        require(block.timestamp - timestamp <= MAX_LATENCY, "cell expired");

        bytes32 cellId = keccak256(abi.encodePacked(sender, qos, payloadHash, timestamp, nonce));
        require(!usedCells[cellId], "replayed cell");
        usedCells[cellId] = true;

        bytes32 msgHash = getEthSignedMessageHash(cellId);
        require(recoverSigner(msgHash, signature) == sender, "invalid sig");

        emit CellProcessed(sender, qos, payloadHash);
    }

    function getEthSignedMessageHash(bytes32 hash) internal pure returns (bytes32) {
        return keccak256(abi.encodePacked("\x19Ethereum Signed Message:\n32", hash));
    }

    function recoverSigner(bytes32 hash, bytes memory sig) internal pure returns (address) {
        require(sig.length == 65, "bad sig len");
        bytes32 r; bytes32 s; uint8 v;
        assembly {
            r := mload(add(sig, 32))
            s := mload(add(sig, 64))
            v := byte(0, mload(add(sig, 96)))
        }
        return ecrecover(hash, v, r, s);
    }
}
