pragma solidity ^0.8.21;

contract LowIntegrity {
    address public highIntegrityContract;

    constructor(address _highIntegrityContract) {
        highIntegrityContract = _highIntegrityContract;
    }

    function injectData(bytes memory maliciousData) external {
        HighIntegrity(highIntegrityContract).writeData(maliciousData);
    }
}

interface HighIntegrity {
    function writeData(bytes memory data) external;
}
