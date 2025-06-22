contract ZombieSpawner {
    event ZombieDeployed(address clone);

    function deploy(bytes32 salt, address logic) external returns (address clone) {
        bytes20 target = bytes20(logic);
        assembly {
            let ptr := mload(0x40)
            mstore(ptr, 0x3d602d80600a3d3981f3)
            mstore(add(ptr, 0x14), shl(0x60, target))
            mstore(add(ptr, 0x28), 0x5af43d82803e903d91602b57fd5bf3)
            clone := create2(0, ptr, 0x37, salt)
        }
        emit ZombieDeployed(clone);
    }
}
