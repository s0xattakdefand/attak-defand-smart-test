// SPDX-License-Identifier: MIT
pragma solidity ^0.8.25;

contract APDUProcessor {
    struct APDU {
        bytes4 selector;
        uint16 length;
        bytes payload;
    }

    event APDUParsed(address indexed sender, bytes4 selector, bytes payload);
    event MalformedAPDU(address indexed sender, string reason);

    uint16 public minLength = 4; // Minimal payload after selector

    function parseAPDU(bytes calldata input) external returns (bool success) {
        if (input.length < 6) {
            emit MalformedAPDU(msg.sender, "Input too short for APDU");
            return false;
        }

        bytes4 selector;
        uint16 len;
        assembly {
            selector := calldataload(input.offset)
            len := calldataload(add(input.offset, 4))
        }

        if (input.length < 6 + len) {
            emit MalformedAPDU(msg.sender, "Declared length too large");
            return false;
        }

        bytes calldata payload = input[6:6 + len];

        // Optional: add selector whitelist here
        if (!_isValidSelector(selector)) {
            emit MalformedAPDU(msg.sender, "Invalid selector");
            return false;
        }

        emit APDUParsed(msg.sender, selector, payload);
        return true;
    }

    function _isValidSelector(bytes4 sel) internal pure returns (bool) {
        return (sel != bytes4(0) && sel != 0xffffffff);
    }
}
