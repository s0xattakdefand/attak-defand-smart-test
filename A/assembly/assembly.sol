// SPDX-License-Identifier: MIT
pragma solidity ^0.8.25;

contract AssemblyExample {
    address public logicContract;

    constructor(address _logic) {
        logicContract = _logic;
    }

    function rawDelegate(bytes calldata data) external payable returns (bytes memory result) {
        address target = logicContract;
        assembly {
            let ptr := mload(0x40)
            let success := delegatecall(gas(), target, add(data.offset, 0x20), calldataload(data.offset), ptr, 0)
            let size := returndatasize()
            returndatacopy(ptr, 0, size)

            switch success
            case 0 {
                revert(ptr, size)
            }
            default {
                return(ptr, size)
            }
        }
    }

    function getSlot(uint256 slot) external view returns (bytes32 val) {
        assembly {
            val := sload(slot)
        }
    }

    function setSlot(uint256 slot, bytes32 value) external {
        assembly {
            sstore(slot, value)
        }
    }
}
