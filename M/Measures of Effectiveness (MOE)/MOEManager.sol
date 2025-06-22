interface ISecurityGateway {
    function getMOE() external view returns (uint256, uint256, uint256);
}

contract MOEManager {
    address[] public gateways;

    function addGateway(address g) external {
        gateways.push(g);
    }

    function aggregate() external view returns (uint256 avgDR, uint256 avgFPR, uint256 avgEff) {
        uint256 dr; uint256 fpr; uint256 eff;
        uint256 len = gateways.length;

        for (uint256 i = 0; i < len; i++) {
            (uint256 a, uint256 b, uint256 c) = ISecurityGateway(gateways[i]).getMOE();
            dr += a; fpr += b; eff += c;
        }

        if (len > 0) {
            avgDR = dr / len;
            avgFPR = fpr / len;
            avgEff = eff / len;
        }
    }
}
