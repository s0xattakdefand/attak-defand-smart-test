interface IEntropyLikelihood {
    function likelihood(bytes4) external view returns (uint256);
}
interface IExploitImpactScore {
    function get(bytes4) external view returns (uint256);
}
interface IAttackSurfaceMap {
    function exposed(bytes4) external view returns (bool);
}

contract RiskAssessmentEngine {
    IEntropyLikelihood public entropyMod;
    IExploitImpactScore public impactMod;
    IAttackSurfaceMap public surfaceMod;

    constructor(address _e, address _i, address _s) {
        entropyMod = IEntropyLikelihood(_e);
        impactMod = IExploitImpactScore(_i);
        surfaceMod = IAttackSurfaceMap(_s);
    }

    function risk(bytes4 sel) public view returns (uint256) {
        if (!surfaceMod.exposed(sel)) return 0;
        return entropyMod.likelihood(sel) * impactMod.get(sel);
    }
}
