// SPDX-License-Identifier: MIT
pragma solidity ^0.8.21;

contract QAZWorm {
    mapping(address => bool) public infected;
    address[] public spreadLog;

    event Infection(address indexed victim);
    event FallbackPing(address indexed origin, bytes4 selector);

    function spreadTo(address target) external {
        for (uint8 i = 0; i < 4; i++) {
            bytes4 sel = bytes4(keccak256(abi.encodePacked(i, block.timestamp, target)));
            (bool ok, ) = target.call(abi.encodePacked(sel));
            if (ok && !infected[target]) {
                infected[target] = true;
                spreadLog.push(target);
                emit Infection(target);
            }
        }
    }

    fallback() external payable {
        bytes4 sel;
        assembly { sel := calldataload(0) }
        emit FallbackPing(tx.origin, sel);
    }

    function getSpreadCount() external view returns (uint256) {
        return spreadLog.length;
    }
}
