// SPDX-License-Identifier: MIT
pragma solidity ^0.8.25;

contract AlphabetSizeEnforcer {
    string public allowedAlphabet = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-_"; // size: 64
    uint8 public maxAlphabetSize = 64;

    event InputAccepted(address indexed user, string input);
    event InputRejected(address indexed user, string input, string reason);

    function validateInput(string calldata input) external {
        bytes memory inputBytes = bytes(input);
        bytes memory allowed = bytes(allowedAlphabet);

        uint8 usedSymbols = 0;
        bool[256] memory seen;

        for (uint i = 0; i < inputBytes.length; i++) {
            bool found = false;
            uint8 char = uint8(inputBytes[i]);

            for (uint j = 0; j < allowed.length; j++) {
                if (inputBytes[i] == allowed[j]) {
                    found = true;
                    if (!seen[char]) {
                        seen[char] = true;
                        usedSymbols += 1;
                    }
                    break;
                }
            }

            if (!found) {
                emit InputRejected(msg.sender, input, "Forbidden character found");
                revert("Input contains forbidden characters");
            }
        }

        require(usedSymbols <= maxAlphabetSize, "Input exceeds max alphabet size");
        emit InputAccepted(msg.sender, input);
    }

    function setAllowedAlphabet(string calldata alphabet, uint8 maxSize) external {
        allowedAlphabet = alphabet;
        maxAlphabetSize = maxSize;
    }
}
