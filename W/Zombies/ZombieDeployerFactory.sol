// SPDX-License-Identifier: MIT
pragma solidity ^0.8.21;

contract Zombie {
    address public owner;
    bool public active;
    bytes4 public reactivationSelector;

    event Reactivated(address indexed caller, bytes4 selector);

    constructor(bytes4 _selector) payable {
        owner = msg.sender;
        reactivationSelector = _selector;
    }

    fallback() external payable {
        if (!active && msg.sig == reactivationSelector) {
            active = true;
            emit Reactivated(msg.sender, msg.sig);
        }
    }
}

contract ZombieDeployerFactory {
    mapping(bytes4 => address) public zombies;
    event ZombieDeployed(bytes4 selector, address zombie);

    function deployZombie(bytes4 selector, bytes32 salt) external returns (address clone) {
        bytes memory bytecode = abi.encodePacked(
            type(Zombie).creationCode,
            abi.encode(selector)
        );
        assembly {
            clone := create2(0, add(bytecode, 0x20), mload(bytecode), salt)
        }
        require(clone != address(0), "Deployment failed");
        zombies[selector] = clone;
        emit ZombieDeployed(selector, clone);
    }

    function computeAddress(bytes4 selector, bytes32 salt) external view returns (address predicted) {
        bytes memory bytecode = abi.encodePacked(
            type(Zombie).creationCode,
            abi.encode(selector)
        );
        bytes32 hash = keccak256(abi.encodePacked(
            bytes1(0xff),
            address(this),
            salt,
            keccak256(bytecode)
        ));
        predicted = address(uint160(uint256(hash)));
    }
}
