// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

interface IERC20 {
    function transfer(address to, uint256 amount) external returns (bool);
    function approve(address spender, uint256 amount) external returns (bool);
    function balanceOf(address account) external view returns (uint256);
}

contract ConformanceMethodologyHarness {
    event TestPassed(string test);
    event TestFailed(string test);

    function testERC20Transfer(address token, address to, uint256 amount) external {
        try IERC20(token).transfer(to, amount) returns (bool result) {
            if (result) emit TestPassed("ERC20.transfer");
            else emit TestFailed("ERC20.transfer returned false");
        } catch {
            emit TestFailed("ERC20.transfer reverted");
        }
    }

    function testERC20Approve(address token, address spender, uint256 amount) external {
        try IERC20(token).approve(spender, amount) returns (bool result) {
            if (result) emit TestPassed("ERC20.approve");
            else emit TestFailed("ERC20.approve returned false");
        } catch {
            emit TestFailed("ERC20.approve reverted");
        }
    }

    function testInterfaceSupport(address contractAddr, bytes4 interfaceId) external {
        (bool success, bytes memory data) = contractAddr.staticcall(
            abi.encodeWithSignature("supportsInterface(bytes4)", interfaceId)
        );

        if (success && data.length >= 32 && abi.decode(data, (bool))) {
            emit TestPassed("supportsInterface");
        } else {
            emit TestFailed("supportsInterface failed or unsupported");
        }
    }
}
