// SPDX-License-Identifier: MIT
pragma solidity ^0.8.21;

interface IResponseStrategy {
    function respond(bytes4 selector, address origin, string calldata typeHint) external;
}

contract ThreatResponseRouter {
    IResponseStrategy public strategy;

    event ThreatRouted(bytes4 selector, address origin, string typeHint);

    constructor(address _strategy) {
        strategy = IResponseStrategy(_strategy);
    }

    function route(bytes4 selector, address origin, string calldata typeHint) external {
        strategy.respond(selector, origin, typeHint);
        emit ThreatRouted(selector, origin, typeHint);
    }
}
