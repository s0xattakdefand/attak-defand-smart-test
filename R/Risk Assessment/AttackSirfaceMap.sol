contract AttackSurfaceMap {
    mapping(bytes4 => bool) public isPublic;

    function register(bytes4 selector, bool exposed) external {
        isPublic[selector] = exposed;
    }

    function exposed(bytes4 sel) external view returns (bool) {
        return isPublic[sel];
    }
}
