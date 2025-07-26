// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

// DeliveryStatusNotification contract for tracking and notifying delivery statuses
contract DeliveryStatusNotification {
    // Owner of the contract (e.g., logistics company or administrator)
    address public owner;

    // Enum to represent delivery status
    enum DeliveryStatus { Pending, Shipped, InTransit, Delivered, Failed }

    // Structure to store shipment details
    struct Shipment {
        bytes32 shipmentId; // Unique identifier for the shipment
        address sender; // Address of the sender
        address recipient; // Address of the recipient
        bytes32 packageHash; // Hash of package details (e.g., contents, weight)
        DeliveryStatus status; // Current status of the shipment
        uint256 createdAt; // Timestamp when shipment was created
        uint256 updatedAt; // Timestamp of last status update
        bool exists; // Flag to check if shipment exists
    }

    // Mapping to store shipments by shipment ID
    mapping(bytes32 => Shipment) public shipments;

    // Mapping to store authorized couriers
    mapping(address => bool) public couriers;

    // Event emitted when a shipment is created
    event ShipmentCreated(bytes32 indexed shipmentId, address sender, address recipient, bytes32 packageHash, uint256 timestamp);

    // Event emitted when a shipment status is updated
    event StatusUpdated(bytes32 indexed shipmentId, DeliveryStatus status, uint256 timestamp);

    // Event emitted when a courier is added or removed
    event CourierUpdated(address indexed courier, bool authorized, uint256 timestamp);

    // Modifier to restrict functions to the contract owner
    modifier onlyOwner() {
        require(msg.sender == owner, "Only owner can call this function");
        _;
    }

    // Modifier to restrict functions to authorized couriers
    modifier onlyCourier() {
        require(couriers[msg.sender], "Only authorized couriers can call this function");
        _;
    }

    // Modifier to check if a shipment exists
    modifier shipmentExists(bytes32 shipmentId) {
        require(shipments[shipmentId].exists, "Shipment does not exist");
        _;
    }

    // Constructor to set the owner
    constructor() {
        owner = msg.sender;
        couriers[msg.sender] = true; // Owner is a courier by default
    }

    // Function to create a new shipment
    function createShipment(
        bytes32 shipmentId,
        address recipient,
        bytes32 packageHash
    ) external {
        require(!shipments[shipmentId].exists, "Shipment ID already exists");
        require(recipient != address(0), "Recipient cannot be zero address");

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

    // Function to update shipment status
    function updateStatus(bytes32 shipmentId, DeliveryStatus status) external onlyCourier shipmentExists(shipmentId) {
        require(status != shipments[shipmentId].status, "Status must be different");
        require(uint(status) <= uint(DeliveryStatus.Failed), "Invalid status");

        shipments[shipmentId].status = status;
        shipments[shipmentId].updatedAt = block.timestamp;

        emit StatusUpdated(shipmentId, status, block.timestamp);
    }

    // Function to add or remove a courier
    function setCourier(address courier, bool authorized) external onlyOwner {
        require(courier != address(0), "Courier cannot be zero address");
        require(couriers[courier] != authorized, "Courier status already set");

        couriers[courier] = authorized;
        emit CourierUpdated(courier, authorized, block.timestamp);
    }

    // Function to verify package hash
    function verifyPackage(bytes32 shipmentId, bytes32 packageHash) external view shipmentExists(shipmentId) returns (bool) {
        return shipments[shipmentId].packageHash == packageHash;
    }

    // Function to get shipment details
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
            msg.sender == owner ||
            msg.sender == shipments[shipmentId].sender ||
            msg.sender == shipments[shipmentId].recipient ||
            couriers[msg.sender],
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

    // Function to transfer ownership
    function transferOwnership(address newOwner) external onlyOwner {
        require(newOwner != address(0), "New owner cannot be zero address");
        owner = newOwner;
        couriers[newOwner] = true; // New owner becomes a courier
        couriers[owner] = false; // Remove old owner as courier
    }
}