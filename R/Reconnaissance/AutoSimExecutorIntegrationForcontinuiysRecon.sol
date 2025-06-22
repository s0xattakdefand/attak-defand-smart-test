interface ISelectorScanner {
    function scan(address target, uint8 rounds) external;
}

contract AutoSimExecutor {
    address[] public targets;

    function add(address t) external {
        targets.push(t);
    }

    function runRecon(address scanner) external {
        for (uint i = 0; i < targets.length; i++) {
            ISelectorScanner(scanner).scan(targets[i], 16);
        }
    }
}
