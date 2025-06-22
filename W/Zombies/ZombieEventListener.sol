contract ZombieEventListener {
    event Drift(bytes4 selector, address origin, string msg);

    fallback() external {
        emit Drift(msg.sig, tx.origin, "Zombie fallback hit");
    }

    receive() external payable {
        emit Drift(0x00000000, tx.origin, "Zombie received ETH");
    }
}
