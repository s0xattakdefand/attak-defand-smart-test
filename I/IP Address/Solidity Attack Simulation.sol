pragma solidity ^0.8.21;

interface IPProtected {
    function submitRequest(string memory fakeIP) external;
}

contract IPSpoof {
    IPProtected public target;

    constructor(address _target) {
        target = IPProtected(_target);
    }

    function spoofCall() external {
        target.submitRequest("192.168.0.1"); // Pretend to be whitelisted
    }
}
