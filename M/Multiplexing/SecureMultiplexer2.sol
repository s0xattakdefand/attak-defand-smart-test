function reorderBatch(address[] calldata targets, bytes[] calldata payloads)
    external
    view
    returns (address[] memory reorderedT, bytes[] memory reorderedP)
{
    uint256 len = targets.length;
    reorderedT = new address[](len);
    reorderedP = new bytes[](len);
    uint256[] memory scores = new uint256[](len);

    for (uint256 i = 0; i < len; i++) {
        bytes4 selector;
        assembly {
            selector := calldataload(add(payloads[i], 0x20))
        }

        (uint256 calls, uint256 fails) = getStats(selector);
        scores[i] = calls == 0 ? 0 : (fails * 1e4) / calls; // failure rate

        reorderedT[i] = targets[i];
        reorderedP[i] = payloads[i];
    }

    // Selection sort (simple)
    for (uint256 i = 0; i < len; i++) {
        for (uint256 j = i + 1; j < len; j++) {
            if (scores[j] > scores[i]) {
                (scores[i], scores[j]) = (scores[j], scores[i]);
                (reorderedT[i], reorderedT[j]) = (reorderedT[j], reorderedT[i]);
                (reorderedP[i], reorderedP[j]) = (reorderedP[j], reorderedP[i]);
            }
        }
    }
}
