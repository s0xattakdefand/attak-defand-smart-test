bytes32 id = keccak256("TreasuryModule_v1");
bytes32 configHash = keccak256(abi.encodePacked(
    treasuryAddr,
    logicHash,
    roleAssignment
));

crtm.measure(id, configHash);
crtm.seal();

// Later: runtime validator
bool valid = crtm.verify(id, keccak256(...));
