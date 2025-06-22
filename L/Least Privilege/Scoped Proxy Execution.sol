pragma solidity ^0.8.21;

contract ScopedForwarder {
    address public target;
    mapping(bytes4 => bool) public allowedFunctions;

    constructor(address _target) {
        target = _target;
    }

    function allowFunction(bytes4 selector) external {
        allowedFunctions[selector] = true;
    }

    function forward(bytes calldata data) external {
        bytes4 selector;
        assembly {
            selector := calldataload(data.offset)
        }
        require(allowedFunctions[selector], "Function not allowed");

        (bool success, ) = target.call(data);
        require(success, "Forward failed");
    }
}
