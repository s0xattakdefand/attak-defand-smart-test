// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import "./CoreSpecController.sol";

contract ExampleAddendum is ICoreAddendum {
    event SpecApplied(address user, string note);

    function applySpec(address user, bytes calldata data) external override returns (bool) {
        string memory note = abi.decode(data, (string));
        emit SpecApplied(user, note);
        return true;
    }
}
