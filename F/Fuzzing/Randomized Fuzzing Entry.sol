// Simulated pseudocode, actual fuzzing via Foundry or Echidna:

for (i = 0; i < 1000; i++) {
    uint256 x = rand(0, 1e6);
    contract.update(x);
}
