// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

interface IERC20 {
    function approve(address spender, uint256 amount) external returns (bool);
    function transferFrom(address, address, uint256) external returns (bool);
}

contract HoneymonkeyApprovalTester {
    event AbuseDetected(address token, address spender);
    event ApprovalSafe(address token);

    function test(address token, address spender) external {
        IERC20(token).approve(spender, 1 ether);

        // Try to simulate malicious pull (off-chain or later)
        try IERC20(token).transferFrom(address(this), msg.sender, 0.5 ether) {
            emit AbuseDetected(token, spender); // Only if abused
        } catch {
            emit ApprovalSafe(token); // No exploit occurred
        }
    }

    receive() external payable {}
}
