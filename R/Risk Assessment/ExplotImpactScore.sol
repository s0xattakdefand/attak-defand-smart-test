contract ExploitImpactScore {
    mapping(bytes4 => uint256) public impact;

    function set(bytes4 sel, uint256 value) external {
        impact[sel] = value;
    }

    function get(bytes4 sel) external view returns (uint256) {
        return impact[sel];
    }
}
