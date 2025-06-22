// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

interface IERC20 {
    function transfer(address to, uint256 amount) external returns (bool);
    function approve(address spender, uint256 amount) external returns (bool);
    function totalSupply() external view returns (uint256);
    function balanceOf(address who) external view returns (uint256);
}

contract ERC20ConformanceTester {
    event TestPassed(string test);
    event TestFailed(string test);

    function testTransferConformance(address token, address recipient, uint256 amount) external {
        try IERC20(token).transfer(recipient, amount) returns (bool ok) {
            if (ok) {
                emit TestPassed("transfer");
            } else {
                emit TestFailed("transfer returned false");
            }
        } catch {
            emit TestFailed("transfer reverted");
        }
    }

    function testApproveConformance(address token, address spender, uint256 amount) external {
        try IERC20(token).approve(spender, amount) returns (bool ok) {
            if (ok) {
                emit TestPassed("approve");
            } else {
                emit TestFailed("approve returned false");
            }
        } catch {
            emit TestFailed("approve reverted");
        }
    }
}
