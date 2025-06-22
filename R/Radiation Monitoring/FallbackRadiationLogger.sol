contract FallbackRadiationLogger {
    mapping(address => uint256) public fallbackCount;

    event FallbackRadiation(address indexed origin, bytes4 selector, uint256 count);

    fallback() external payable {
        fallbackCount[tx.origin]++;
        emit FallbackRadiation(tx.origin, msg.sig, fallbackCount[tx.origin]);
    }
}
