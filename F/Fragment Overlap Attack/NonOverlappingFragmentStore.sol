// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

contract NonOverlappingFragmentStore {
    struct Fragment {
        uint256 offset;
        uint256 length;
        string data;
        bool exists;
    }

    mapping(uint256 => Fragment) public fragments;
    uint256 public totalSize;

    modifier noOverlap(uint256 offset, uint256 length) {
        for (uint256 i = 0; i < totalSize; i++) {
            Fragment storage f = fragments[i];
            if (f.exists) {
                bool overlap = (
                    (offset >= f.offset && offset < f.offset + f.length) ||
                    (f.offset >= offset && f.offset < offset + length)
                );
                require(!overlap, "Overlap detected");
            }
        }
        _;
    }

    function storeFragment(uint256 offset, string calldata data)
        external
        noOverlap(offset, bytes(data).length)
    {
        fragments[totalSize] = Fragment(offset, bytes(data).length, data, true);
        totalSize++;
    }

    function readFragment(uint256 index) external view returns (Fragment memory) {
        return fragments[index];
    }
}
