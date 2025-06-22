pragma solidity ^0.8.21;

interface MessageStorage {
    function retrieveMessage(address recipient) external returns (string memory);
}

contract MessageInterceptor {
    MessageStorage public storageContract;

    constructor(address _storageContract) {
        storageContract = MessageStorage(_storageContract);
    }

    function intercept(address victim) external returns (string memory) {
        // Attempt unauthorized retrieval
        return storageContract.retrieveMessage(victim);
    }
}
