interface IAccessControl {
    function hasRole(bytes32 role, address account) external view returns (bool);
}

contract RoleMapper {
    function mapRoles(address target, bytes32[] calldata roles, address[] calldata addrs) external view returns (bool[][] memory) {
        bool[][] memory matrix = new bool[][](roles.length);
        for (uint256 i = 0; i < roles.length; i++) {
            bool[] memory row = new bool[](addrs.length);
            for (uint256 j = 0; j < addrs.length; j++) {
                row[j] = IAccessControl(target).hasRole(roles[i], addrs[j]);
            }
            matrix[i] = row;
        }
        return matrix;
    }
}
