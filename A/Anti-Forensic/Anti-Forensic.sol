// SPDX-License-Identifier: MIT
pragma solidity ^0.8.25;

contract AntiForensicDetector {
    struct ExecutionTrace {
        address caller;
        uint256 blockNumber;
        bytes4 selector;
        bytes32 metadataHash;
    }

    mapping(bytes32 => bool) public knownHashes;
    mapping(address => ExecutionTrace[]) public traceLog;
    mapping(address => bool) public flagged;

    event ExecutionTraced(address indexed target, bytes4 selector, bytes32 metadata);
    event ForensicAlert(address indexed source, string reason);

    function traceExecution(bytes calldata payload) external {
        bytes4 selector;
        bytes32 metadata = keccak256(payload);

        assembly {
            selector := calldataload(payload.offset)
        }

        if (knownHashes[metadata]) {
            emit ForensicAlert(msg.sender, "Known anti-forensic payload reused");
            flagged[msg.sender] = true;
        }

        traceLog[msg.sender].push(ExecutionTrace({
            caller: msg.sender,
            blockNumber: block.number,
            selector: selector,
            metadataHash: metadata
        }));

        emit ExecutionTraced(msg.sender, selector, metadata);
        knownHashes[metadata] = true;
    }

    function getTrace(address source) external view returns (ExecutionTrace[] memory) {
        return traceLog[source];
    }

    function isFlagged(address addr) external view returns (bool) {
        return flagged[addr];
    }
}
