pragma solidity ^0.8.21;

interface TargetInterface {
    function execute(bytes calldata payload) external;
}

contract StaticForwarder {
    address public constant TARGET = 0xAbC...123; // predefined secure target

    function forward(bytes calldata data) external {
        TargetInterface(TARGET).execute(data);
    }
}
