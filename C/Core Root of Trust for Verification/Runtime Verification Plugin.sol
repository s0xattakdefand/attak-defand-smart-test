pragma solidity ^0.8.24;

interface ICRTV {
    function verify(bytes32 hash, string calldata context) external returns (bool);
}

contract VerifiedActionModule {
    ICRTV public immutable crtv;

    constructor(address _crtv) {
        crtv = ICRTV(_crtv);
    }

    function execute(bytes32 configHash, string calldata context) external {
        require(crtv.verify(configHash, context), "Verification failed");
        // Safe to proceed
    }
}
