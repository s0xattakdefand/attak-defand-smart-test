pragma solidity ^0.8.21;

contract BackdoorMonitor {
    mapping(address => bool) public flaggedContracts;

    event ContractFlagged(address contractAddr, string reason);

    function simulateCall(address suspicious) external {
        (bool success,) = suspicious.call(abi.encodeWithSignature("maliciousBackdoor()"));
        if (success) {
            flaggedContracts[suspicious] = true;
            emit ContractFlagged(suspicious, "Backdoor detected");
        }
    }
}
