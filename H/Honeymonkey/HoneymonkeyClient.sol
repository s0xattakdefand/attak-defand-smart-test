// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

interface IERC20 {
    function approve(address spender, uint256 amount) external returns (bool);
    function transfer(address to, uint256 amount) external returns (bool);
}

contract HoneymonkeyClient {
    address public controller;
    mapping(address => bool) public tested;

    event ApproveSucceeded(address indexed token, address indexed target);
    event ApproveFailed(address indexed token, string reason);
    event TransferFailed(address indexed token, string reason);

    modifier onlyController() {
        require(msg.sender == controller, "Not controller");
        _;
    }

    constructor() {
        controller = msg.sender;
    }

    function testToken(address token, address target) external onlyController {
        require(!tested[token], "Already tested");
        tested[token] = true;

        try IERC20(token).approve(target, 1e18) {
            emit ApproveSucceeded(token, target);
        } catch Error(string memory reason) {
            emit ApproveFailed(token, reason);
        }

        try IERC20(token).transfer(target, 1e18) {
            // Log nothing if successful (normal)
        } catch Error(string memory reason) {
            emit TransferFailed(token, reason);
        }
    }

    function rescueETH() external onlyController {
        payable(controller).transfer(address(this).balance);
    }

    receive() external payable {}
}
