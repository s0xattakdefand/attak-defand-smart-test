// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

contract OrderedFragmentStore {
    struct Fragment {
        uint256 offset;
        string data;
        bool exists;
    }

    mapping(uint256 => Fragment) public fragments;
    uint256 public totalSize;

    event FragmentStored(uint256 indexed offset, string data);

    function storeFragment(uint256 offset, string calldata data) external {
        require(!fragments[offset].exists, "Offset already used");
        fragments[offset] = Fragment(offset, data, true);
        totalSize++;
        emit FragmentStored(offset, data);
    }

    function getFragment(uint256 offset) external view returns (string memory) {
        require(fragments[offset].exists, "Fragment missing");
        return fragments[offset].data;
    }
}
