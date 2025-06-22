pragma solidity ^0.8.21;

contract ExecutionKernel {
    address public executor;

    constructor() {
        executor = msg.sender;
    }

    modifier onlyExecutor() {
        require(msg.sender == executor, "Not executor");
        _;
    }

    function execute(address target, bytes calldata data) external onlyExecutor {
        (bool success, ) = target.call(data);
        require(success, "Execution failed");
    }
}
