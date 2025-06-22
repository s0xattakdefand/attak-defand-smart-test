// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

contract SanitizingForwardProxy {
    address public validator;

    constructor(address _validator) {
        validator = _validator;
    }

    function forward(address target, bytes calldata data) external returns (bytes memory) {
        require(validate(data), "Sanitized proxy: input rejected");
        (bool success, bytes memory result) = target.call(data);
        require(success, "Call failed");
        return result;
    }

    function validate(bytes calldata data) internal view returns (bool) {
        // Example: reject calls to self-destruct or known malicious functions
        bytes4 selector;
        assembly {
            selector := calldataload(data.offset)
        }
        return selector != bytes4(0xff); // Fake example
    }
}
