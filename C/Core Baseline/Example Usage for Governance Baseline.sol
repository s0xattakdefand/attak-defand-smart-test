bytes32 key = keccak256("Governance");
address governanceContract = 0x...;
bytes32 configHash = keccak256(abi.encodePacked("v1.0", governanceContract));

baselineRegistry.registerBaseline(key, governanceContract, configHash);
baselineRegistry.approveBaseline(key);
