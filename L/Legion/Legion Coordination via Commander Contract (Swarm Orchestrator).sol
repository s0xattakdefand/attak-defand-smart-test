pragma solidity ^0.8.21;

interface ILegion {
    function snipe() external payable;
}

contract LegionCommander {
    ILegion[] public agents;

    function registerAgent(address agent) external {
        agents.push(ILegion(agent));
    }

    function executeSwarm() external payable {
        for (uint i = 0; i < agents.length; i++) {
            agents[i].snipe{value: msg.value / agents.length}();
        }
    }
}
