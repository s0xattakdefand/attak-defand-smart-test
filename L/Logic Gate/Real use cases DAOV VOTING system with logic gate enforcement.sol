// DAO Access requires: isMember AND (isActive OR hasDelegate)
contract DaoLogicAccess {
    function canVote(
        bool isMember,
        bool isActive,
        bool hasDelegate
    ) external pure returns (bool) {
        return isMember && (isActive || hasDelegate); // AND-OR combo
    }
}
