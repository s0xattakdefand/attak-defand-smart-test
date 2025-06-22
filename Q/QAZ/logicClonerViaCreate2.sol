// SPDX-License-Identifier: MIT
pragma solidity ^0.8.21;

contract QAZPayloadFactory {
    address public template;
    mapping(address => address) public deployed;

    event PayloadDeployed(address indexed logicClone);

    constructor(address _template) {
        template = _template;
    }

    function deployClone(bytes32 salt) external returns (address) {
        bytes20 target = bytes20(template);
        address clone;
        assembly {
            let ptr := mload(0x40)
            mstore(ptr, 0x3d602d80600a3d3981f3) // prefix
            mstore(add(ptr, 0x14), shl(0x60, target)) // logic
            mstore(add(ptr, 0x28), 0x5af43d82803e903d91602b57fd5bf3) // suffix
            clone := create2(0, ptr, 0x37, salt)
        }
        require(clone != address(0), "CREATE2 failed");
        deployed[clone] = template;
        emit PayloadDeployed(clone);
        return clone;
    }
}
