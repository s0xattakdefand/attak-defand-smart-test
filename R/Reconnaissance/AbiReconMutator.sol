// SPDX-License-Identifier: MIT
pragma solidity ^0.8.21;

contract ABIReconMutator {
    struct ABIHit {
        bytes4 selector;
        string guessedName;
        bool success;
    }

    ABIHit[] public hits;

    event ABIProbed(bytes4 selector, string guessedName, bool success);

    function mutateAndProbe(address target, string calldata guess, string[] calldata suffixes) external {
        for (uint256 i = 0; i < suffixes.length; i++) {
            string memory combined = string.concat(guess, suffixes[i], "()");
            bytes4 sel = bytes4(keccak256(bytes(combined)));
            (bool ok, ) = target.call(abi.encodePacked(sel));
            hits.push(ABIHit(sel, combined, ok));
            emit ABIProbed(sel, combined, ok);
        }
    }

    function getHits() external view returns (ABIHit[] memory) {
        return hits;
    }
}
