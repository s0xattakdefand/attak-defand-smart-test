contract OpcodeRadiationMonitor {
    event OpcodeRadiation(bytes4 selector, uint256 gasUsed, uint8 score);

    function monitor(address target, bytes calldata payload) external {
        uint256 gasStart = gasleft();
        (bool ok, ) = target.call(payload);
        uint256 gasUsed = gasStart - gasleft();
        bytes4 sel = bytes4(payload);

        uint8 score = gasUsed > 150_000 ? 9 : gasUsed > 80_000 ? 6 : 2;
        emit OpcodeRadiation(sel, gasUsed, score);
    }
}
