// SPDX-License-Identifier: MIT
pragma solidity ^0.8.25;

contract AlphabetGuard {
    string public constant allowedAlphabet = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-_";

    event ValidInputReceived(address indexed sender, string input);
    event RejectedInput(address indexed sender, string input, string reason);

    function validateInput(string calldata input) external {
        bytes memory inputBytes = bytes(input);
        bytes memory allowed = bytes(allowedAlphabet);

        for (uint i = 0; i < inputBytes.length; i++) {
            bool found = false;
            for (uint j = 0; j < allowed.length; j++) {
                if (inputBytes[i] == allowed[j]) {
                    found = true;
                    break;
                }
            }
            if (!found) {
                emit RejectedInput(msg.sender, input, "Invalid character detected");
                revert("Input contains forbidden character");
            }
        }

        emit ValidInputReceived(msg.sender, input);
    }
}
