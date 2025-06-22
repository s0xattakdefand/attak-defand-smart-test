// SPDX-License-Identifier: MIT
pragma solidity ^0.8.25;

contract AmbiguityRuleEnforcer {
    mapping(bytes4 => bool) public allowedSelectors;
    mapping(bytes4 => string) public selectorNames;

    event UnknownSelectorDetected(address sender, bytes4 selector, uint256 calldataLength);
    event AmbiguousSelectorBlocked(bytes4 selector);
    event FallbackCalled(bytes data);

    constructor() {
        // Example: Register known safe selectors
        allowedSelectors[bytes4(keccak256("safeTransfer(address,uint256)"))] = true;
        selectorNames[bytes4(keccak256("safeTransfer(address,uint256)"))] = "safeTransfer";
    }

    fallback() external payable {
        bytes4 selector;
        assembly {
            selector := calldataload(0)
        }

        if (!allowedSelectors[selector]) {
            emit UnknownSelectorDetected(msg.sender, selector, msg.data.length);
            revert("Ambiguity Rule: Unknown or unsafe selector");
        }

        emit FallbackCalled(msg.data);
    }

    /// @notice Admin can explicitly approve a selector
    function allowSelector(bytes4 selector, string calldata name) external {
        allowedSelectors[selector] = true;
        selectorNames[selector] = name;
    }

    /// @notice Admin can remove a selector from the allowlist
    function blockSelector(bytes4 selector) external {
        allowedSelectors[selector] = false;
        emit AmbiguousSelectorBlocked(selector);
    }

    /// @notice Get function name by selector (if known)
    function getSelectorName(bytes4 selector) external view returns (string memory) {
        return selectorNames[selector];
    }
}
