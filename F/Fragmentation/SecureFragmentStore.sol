// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

contract SecureFragmentStore {
    struct Fragment {
        uint256 offset;
        uint256 length;
        string data;
        bool exists;
    }

    mapping(uint256 => Fragment) public fragments;
    uint256 public fragmentCount;

    modifier validOffset(uint256 offset, uint256 length) {
        for (uint256 i = 0; i < fragmentCount; i++) {
            Fragment memory f = fragments[i];
            bool overlap = (
                (offset >= f.offset && offset < f.offset + f.length) ||
                (f.offset >= offset && f.offset < offset + length)
            );
            require(!overlap, "Fragment overlap");
        }
        _;
    }

    function storeFragment(uint256 offset, string calldata data)
        external
        validOffset(offset, bytes(data).length)
    {
        fragments[fragmentCount] = Fragment(offset, bytes(data).length, data, true);
        fragmentCount++;
    }

    function getFragment(uint256 index) external view returns (Fragment memory) {
        return fragments[index];
    }
}
