// SPDX-License-Identifier: MIT
pragma solidity ^0.8.21;

contract ReconAgent {
    struct ReconHit {
        address target;
        bytes4 selector;
        bool success;
    }

    ReconHit[] public logs;

    event Probed(address indexed target, bytes4 selector, bool success);

    function probe(address target, bytes4 selector) public {
        (bool ok, ) = target.call(abi.encodePacked(selector));
        logs.push(ReconHit(target, selector, ok));
        emit Probed(target, selector, ok);
    }

    function batchRecon(address target, uint256 seed, uint8 rounds) external {
        for (uint8 i = 0; i < rounds; i++) {
            bytes4 sel = bytes4(keccak256(abi.encodePacked(target, seed, i)));
            probe(target, sel);
        }
    }

    function getLogs() external view returns (ReconHit[] memory) {
        return logs;
    }
}
