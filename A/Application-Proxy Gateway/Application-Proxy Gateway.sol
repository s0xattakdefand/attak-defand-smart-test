// SPDX-License-Identifier: MIT
pragma solidity ^0.8.25;

contract ApplicationProxyGateway {
    address public logic;
    mapping(bytes4 => bool) public allowedSelectors;
    address public admin;

    event CallForwarded(address indexed caller, bytes4 selector);
    event CallBlocked(address indexed caller, bytes4 selector, string reason);
    event LogicUpgraded(address indexed newLogic);

    constructor(address _logic) {
        logic = _logic;
        admin = msg.sender;
    }

    modifier onlyAdmin() {
        require(msg.sender == admin, "Not admin");
        _;
    }

    function setLogic(address newLogic) external onlyAdmin {
        require(newLogic != address(0), "Invalid address");
        logic = newLogic;
        emit LogicUpgraded(newLogic);
    }

    function allowSelector(bytes4 selector) external onlyAdmin {
        allowedSelectors[selector] = true;
    }

    function blockSelector(bytes4 selector) external onlyAdmin {
        allowedSelectors[selector] = false;
    }

    fallback() external payable {
        bytes4 selector;
        assembly {
            selector := calldataload(0)
        }

        if (!allowedSelectors[selector]) {
            emit CallBlocked(msg.sender, selector, "Selector not allowed");
            revert("Proxy: Selector not allowed");
        }

        address target = logic;
        require(target != address(0), "No logic assigned");

        emit CallForwarded(msg.sender, selector);

        assembly {
            let ptr := mload(0x40)
            calldatacopy(ptr, 0, calldatasize())
            let result := delegatecall(gas(), target, ptr, calldatasize(), 0, 0)
            let size := returndatasize()
            returndatacopy(ptr, 0, size)
            switch result
                case 0 { revert(ptr, size) }
                default { return(ptr, size) }
        }
    }

    receive() external payable {}
}
