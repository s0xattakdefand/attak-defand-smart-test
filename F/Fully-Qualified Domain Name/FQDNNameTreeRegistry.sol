// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

contract FQDNNameTreeRegistry {
    struct Node {
        address owner;
        mapping(string => Node) children;
    }

    Node private root;

    function registerFQDN(string[] calldata parts) external {
        Node storage current = root;
        for (uint256 i = parts.length; i > 0; i--) {
            string memory label = parts[i - 1];
            current = current.children[label];
        }

        require(current.owner == address(0), "Already taken");
        current.owner = msg.sender;
    }

    function resolveFQDN(string[] calldata parts) external view returns (address) {
        Node storage current = root;
        for (uint256 i = parts.length; i > 0; i--) {
            current = current.children[parts[i - 1]];
        }
        return current.owner;
    }
}
