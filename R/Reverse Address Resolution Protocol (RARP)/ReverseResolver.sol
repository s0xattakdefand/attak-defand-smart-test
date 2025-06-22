// SPDX-License-Identifier: MIT
pragma solidity ^0.8.21;

contract ReverseResolver {
    struct Meta {
        string label;
        string tag;
        string role;
    }

    mapping(address => Meta) public addrLabels;
    mapping(bytes4 => string) public selectorNames;

    event AddressLabeled(address indexed who, string label, string tag);
    event SelectorNamed(bytes4 indexed sel, string name);

    function labelAddress(address who, string calldata label, string calldata tag, string calldata role) external {
        addrLabels[who] = Meta(label, tag, role);
        emit AddressLabeled(who, label, tag);
    }

    function nameSelector(bytes4 selector, string calldata name) external {
        selectorNames[selector] = name;
        emit SelectorNamed(selector, name);
    }

    function reverseAddress(address who) external view returns (Meta memory) {
        return addrLabels[who];
    }

    function reverseSelector(bytes4 sel) external view returns (string memory) {
        return selectorNames[sel];
    }
}
