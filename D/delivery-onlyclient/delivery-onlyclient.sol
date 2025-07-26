// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

// DeliveryOnlyClient contract for client interactions in a delivery system
contract DeliveryOnlyClient {
    // Address of the logistics contract (admin or main contract)
    address public logisticsContract;

    // Enum to represent delivery status
    enum DeliveryStatus { Pending, Shipped, InTransit, Delivered, Failed }

    // Structure to store shipment details
    struct Shipment {
        bytes32 shipmentId; // Unique identifier for the shipment
        address sender; // Address of the sender (client)
        address recipient; // Address of the recipient
        bytes32 packageHash; // Hash of package details (e.g., contents, weight)
        DeliveryStatus status; // Current status of the shipment
        uint256 createdAt; // Timestamp when shipment was created
        uint256 updatedAt; // Timestamp of last status update
        bool exists; // Flag to check if shipment exists
    }

    // Mapping to store shipments by shipment ID
    mapping(bytes32 => Shipment) public shipments;

    // Event emitted when a shipment is created by a client
    event ShipmentCreated(bytes32 indexed shipmentId, address indexed sender, address recipient, bytes32 packageHash, uint256 timestamp);

    // Event emitted when a shipment status is updated (by logistics contract)
    event StatusUpdated(bytes32 indexed shipmentId, DeliveryStatus status, uint256 timestamp);

    // Modifier to restrict functions to the logistics contract
    modifier onlyLogisticsContract() {
        require(msg.sender == logisticsContract, "Only logistics contract can call this function");
        _;
    }

    // Modifier to check if a shipment exists
    modifier shipmentExists(bytes32 shipmentId) {
        require(shipments[shipmentId].exists, "Shipment does not exist");
        _;
    }

    // Constructor to set the logistics contract address
    constructor(address _logisticsContract) {
        require(_logisticsContract != address(0), "Logistics contract cannot be zero address");
        logisticsContract = _logisticsContract;
    }

    // Function for clients to create a new shipment
    function createShipment(
        bytes32 shipmentId,
        address recipient,
        bytes32 packageHash
    ) external {
        require(!shipments[shipmentId].exists, "Shipment ID already exists");
        require(recipient != address(0), "Recipient cannot be zero address");
        require(msg.sender != recipient, "Sender and recipient cannot be the same");

        shipments[shipmentId] = Shipment({
            shipmentId: shipmentId,
            sender: msg.sender,
            recipient: recipient,
            packageHash: packageHash,
            status: DeliveryStatus.Pending,
            createdAt: block.timestamp,
            updatedAt: block.timestamp,
            exists: true
        });

        emit ShipmentCreated(shipmentId, msg.sender, recipient, packageHash, block.timestamp);
    }

    // Function for logistics contract to update shipment status
    function updateStatus(bytes32 shipmentId, DeliveryStatus status) external onlyLogisticsContract shipmentExists(shipmentId) {
        require(status != shipments[shipmentId].status, "Status must be different");
        require(uint(status) <= uint(DeliveryStatus.Failed), "Invalid status");

        shipments[shipmentId].status = status;
        shipments[shipmentId].updatedAt = block.timestamp;

        emit StatusUpdated(shipmentId, status, block.timestamp);
    }

    // Function to verify package hash
    function verifyPackage(bytes32 shipmentId, bytes32 packageHash) external view shipmentExists(shipmentId) returns (bool) {
        return shipments[shipmentId].packageHash == packageHash;
    }

    // Function for clients to view shipment details
    function getShipmentDetails(bytes32 shipmentId)
        external
        view
        shipmentExists(shipmentId)
        returns (
            address sender,
            address recipient,
            bytes32 packageHash,
            DeliveryStatus status,
            uint256 createdAt,
            uint256 updatedAt
        )
    {
        require(
            msg.sender == shipments[shipmentId].sender ||
            msg.sender == shipments[shipmentId].recipient ||
            msg.sender == logisticsContract,
            "Not authorized to view shipment details"
        );

        Shipment memory shipment = shipments[shipmentId];
        return (
            shipment.sender,
            shipment.recipient,
            shipment.packageHash,
            shipment.status,
            shipment.createdAt,
            shipment.updatedAt
        );
    }

    // Function to update the logistics contract address
    function updateLogisticsContract(address newLogisticsContract) external onlyLogisticsContract {
        require(newLogisticsContract != address(0), "New logistics contract cannot be zero address");
        logisticsContract = newLogisticsContract;
    }
}