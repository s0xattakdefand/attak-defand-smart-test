// SPDX-License-Identifier: MIT
pragma solidity ^0.8.21;

contract UniversalRegistry {
    enum EntryType { Address, Selector, Hash, Role }

    struct Entry {
        EntryType kind;
        bytes32 value;
        string tag;
        uint256 addedAt;
        bool active;
    }

    Entry[] public entries;
    mapping(bytes32 => bool) public exists;

    event Registered(bytes32 indexed key, EntryType kind, string tag);
    event Deactivated(bytes32 indexed key);

    function register(EntryType kind, bytes32 value, string calldata tag) external {
        require(!exists[value], "Already exists");
        entries.push(Entry(kind, value, tag, block.timestamp, true));
        exists[value] = true;
        emit Registered(value, kind, tag);
    }

    function deactivate(bytes32 value) external {
        require(exists[value], "Not found");
        exists[value] = false;
        emit Deactivated(value);
    }

    function total() external view returns (uint256) {
        return entries.length;
    }

    function get(uint256 i) external view returns (Entry memory) {
        return entries[i];
    }
}
