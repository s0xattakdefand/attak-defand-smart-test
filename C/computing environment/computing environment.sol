// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

contract EnvironmentGuard {
    address public admin;
    string public environmentType;
    bool public isProduction;

    mapping(address => bool) public blocked;
    mapping(bytes4 => bool) public disallowedSelectors;

    event EnvironmentRegistered(string env, bool isProduction);
    event SuspiciousCall(address actor, bytes4 selector, string reason);
    event SelectorBlocked(bytes4 selector);
    event AddressBlocked(address actor);

    modifier onlyAdmin() {
        require(msg.sender == admin, "Not admin");
        _;
    }

    modifier environmentCheck(bytes calldata data) {
        require(!blocked[msg.sender], "Blocked actor");
        if (data.length >= 4) {
            bytes4 selector = bytes4(data[:4]);
            if (disallowedSelectors[selector]) {
                emit SuspiciousCall(msg.sender, selector, "Disallowed selector");
                blocked[msg.sender] = true;
                emit AddressBlocked(msg.sender);
                revert("Disallowed selector");
            }
        }
        _;
    }

    constructor(string memory env, bool prod) {
        admin = msg.sender;
        environmentType = env;
        isProduction = prod;
        emit EnvironmentRegistered(env, prod);
    }

    function blockSelector(bytes4 selector) external onlyAdmin {
        disallowedSelectors[selector] = true;
        emit SelectorBlocked(selector);
    }

    function blockAddress(address actor) external onlyAdmin {
        blocked[actor] = true;
        emit AddressBlocked(actor);
    }

    function getEnv() external view returns (string memory, bool) {
        return (environmentType, isProduction);
    }
}
