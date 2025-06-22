// SPDX-License-Identifier: MIT
pragma solidity ^0.8.21;

contract zkFaucetTrap {
    mapping(bytes32 => bool) public claimed;
    address public faucetAdmin;

    constructor(address _admin) {
        faucetAdmin = _admin;
    }

    function claim(bytes32 zkId, bytes calldata zkProof) external {
        require(!claimed[zkId], "Already claimed");

        // Pretend zkProof is validated
        claimed[zkId] = true;
        payable(msg.sender).transfer(0.1 ether); // zk reward
    }

    receive() external payable {}
}
