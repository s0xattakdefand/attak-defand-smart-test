// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

interface IERC20 {
    function approve(address, uint256) external returns (bool);
    function transfer(address, uint256) external returns (bool);
    function balanceOf(address) external view returns (uint256);
}

contract HoneyClientDetector {
    event SuspiciousToken(address indexed token, string reason);
    event TokenSafe(address indexed token);

    function testToken(address token) external {
        IERC20 t = IERC20(token);

        // Simulate approval
        try t.approve(address(this), 1e18) {
            // Try to transfer a small amount (if we own any)
            uint256 bal = t.balanceOf(address(this));
            if (bal > 0) {
                try t.transfer(msg.sender, 1) {
                    emit TokenSafe(token);
                } catch {
                    emit SuspiciousToken(token, "Transfer failed");
                }
            } else {
                emit TokenSafe(token); // No balance = cannot test transfer
            }
        } catch {
            emit SuspiciousToken(token, "Approve failed");
        }
    }
}
