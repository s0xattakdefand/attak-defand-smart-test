contract ZombieEOADetector {
    function isZombie(address user) external view returns (bool) {
        return user.code.length == 0 && user.balance > 0;
    }
}
