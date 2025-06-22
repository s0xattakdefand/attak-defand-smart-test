// SPDX-License-Identifier: MIT
pragma solidity ^0.8.21;

contract NATSelectorMapper {
    mapping(bytes4 => uint16) public selectorToPort;
    mapping(uint16 => bytes4) public portToSelector;

    function registerMapping(bytes4 selector, uint16 port) external {
        selectorToPort[selector] = port;
        portToSelector[port] = selector;
    }

    function getSelectorByPort(uint16 port) external view returns (bytes4) {
        return portToSelector[port];
    }

    function getPortBySelector(bytes4 selector) external view returns (uint16) {
        return selectorToPort[selector];
    }
}
