// SPDX-License-Identifier: MIT
pragma solidity ^0.8.21;

contract MultiBridgeRouter {
    address public l1Router;
    address public l2Router;
    address public l3Router;

    mapping(uint256 => address) public chainRouter;

    constructor(address _l1, address _l2, address _l3) {
        l1Router = _l1;
        l2Router = _l2;
        l3Router = _l3;

        chainRouter[1] = _l1; // Ethereum
        chainRouter[10] = _l2; // Optimism
        chainRouter[42161] = _l3; // Arbitrum
    }

    function routeFromChain(uint256 chainId, bytes calldata data) external {
        address router = chainRouter[chainId];
        require(router != address(0), "Unknown router");

        // 💥 Different routers may implement inconsistent auth/logic
        (bool ok, ) = router.call(data);
        require(ok, "Route drift detected");
    }
}
