// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/**
 * @title FastFluxRegistry
 * @notice This contract simulates a Fast Flux network by maintaining a dynamic list of node addresses.
 *         The active node is determined by the current block timestamp and a configurable flux interval.
 *         It can serve as a basis for rotating endpoints in decentralized bridging, dynamic service routing, or load distribution.
 */
contract FastFluxRegistry {
    // The admin who manages the registry (should be secured, e.g. a multisig)
    address public admin;
    // Dynamic list of node addresses (flux nodes)
    address[] public fluxNodes;
    // Time interval (in seconds) after which the active node rotates
    uint256 public fluxInterval;

    // Events for node management and configuration updates
    event NodeAdded(address indexed newNode);
    event NodeRemoved(address indexed removedNode);
    event FluxIntervalUpdated(uint256 newInterval);

    /**
     * @notice Initializes the registry with a specified flux interval.
     * @param _fluxInterval The number of seconds that define each rotation period.
     */
    constructor(uint256 _fluxInterval) {
        admin = msg.sender;
        fluxInterval = _fluxInterval;
    }

    /// @notice Modifier to restrict functions to only the admin.
    modifier onlyAdmin() {
        require(msg.sender == admin, "Not admin");
        _;
    }

    /**
     * @notice Adds a node address to the fast flux pool.
     * @param node The address of the node to add.
     */
    function addNode(address node) external onlyAdmin {
        require(node != address(0), "Invalid address");
        fluxNodes.push(node);
        emit NodeAdded(node);
    }

    /**
     * @notice Removes the node at the specified index from the flux pool.
     * @param index The index of the node in the fluxNodes array.
     */
    function removeNode(uint256 index) external onlyAdmin {
        require(index < fluxNodes.length, "Index out of range");
        address removed = fluxNodes[index];
        // Replace the node being removed with the last node and shorten the array
        fluxNodes[index] = fluxNodes[fluxNodes.length - 1];
        fluxNodes.pop();
        emit NodeRemoved(removed);
    }

    /**
     * @notice Updates the flux interval, controlling how frequently the active node rotates.
     * @param newInterval The new flux interval in seconds.
     */
    function updateFluxInterval(uint256 newInterval) external onlyAdmin {
        require(newInterval > 0, "Invalid interval");
        fluxInterval = newInterval;
        emit FluxIntervalUpdated(newInterval);
    }

    /**
     * @notice Returns the current active node based on block.timestamp.
     * @return The active node address.
     */
    function getActiveNode() public view returns (address) {
        require(fluxNodes.length > 0, "No flux nodes available");
        // Calculate an index based on the block timestamp divided by fluxInterval,
        // and then take modulo with the number of nodes.
        uint256 index = (block.timestamp / fluxInterval) % fluxNodes.length;
        return fluxNodes[index];
    }

    /**
     * @notice For demonstration, forwards a low-level call to the active node.
     * @param data The calldata to forward.
     * @return success True if the call succeeded.
     * @return result The returned data from the call.
     */
    function executeOnActiveNode(bytes calldata data) external returns (bool success, bytes memory result) {
        address activeNode = getActiveNode();
        (success, result) = activeNode.call(data);
    }
}
