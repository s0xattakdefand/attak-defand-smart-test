// SPDX-License-Identifier: MIT
pragma solidity ^0.8.25;

/// Common errors
error Unauthorized();
error WrongState();
error AlreadyDone();
error TooEarly(uint256 readyAt);

/// @title 1. Role‑Based Separation
/// @dev Vulnerable: same role for propose & execute
contract RoleBasedVuln {
    address public admin;
    bytes32 public lastTask;
    event Proposed(bytes32 task);
    event Executed(bytes32 task);

    constructor() { admin = msg.sender; }

    function propose(bytes32 task) external {
        if (msg.sender != admin) revert Unauthorized();
        lastTask = task;
        emit Proposed(task);
    }
    /// no role check → anyone can execute lastTask
    function execute() external {
        bytes32 t = lastTask;
        emit Executed(t);
        // … perform t …
    }
}

/// Hardened: separate proposer & executor
contract RoleBasedSafe {
    mapping(address=>bool) public isProposer;
    mapping(address=>bool) public isExecutor;
    bytes32 public lastTask;
    event Proposed(bytes32 task);
    event Executed(bytes32 task);

    constructor(address proposer, address executor) {
        isProposer[proposer] = true;
        isExecutor[executor] = true;
    }

    function propose(bytes32 task) external {
        if (!isProposer[msg.sender]) revert Unauthorized();
        lastTask = task;
        emit Proposed(task);
    }
    function execute() external {
        if (!isExecutor[msg.sender]) revert Unauthorized();
        bytes32 t = lastTask;
        emit Executed(t);
        // … perform t …
    }
}

/// Demo exploit against RoleBasedVuln
contract Attack_RoleBased {
    RoleBasedVuln public target;
    constructor(RoleBasedVuln _t) { target = _t; }
    function attack() external {
        // bypass role separation: anyone can call execute()
        target.execute();
    }
}



/// @title 2. Dual‑Control Separation
/// @dev Vulnerable: single‑party release
contract DualControlVuln {
    address public payee;
    uint256 public amount;
    event Released(address to, uint256 amt);

    constructor(address _payee) payable {
        payee = _payee;
        amount = msg.value;
    }
    function release() external {
        // no second approval required
        payable(payee).transfer(amount);
        emit Released(payee, amount);
    }
}

/// Hardened: require approvals from both payee & approver
contract DualControlSafe {
    address public payee;
    address public approver;
    uint256 public amount;
    bool    public payeeOK;
    bool    public approverOK;
    event Approved(address who);
    event Released(address to, uint256 amt);

    constructor(address _payee, address _approver) payable {
        payee     = _payee;
        approver  = _approver;
        amount    = msg.value;
    }

    function approve() external {
        if (msg.sender == payee) {
            if (payeeOK) revert AlreadyDone();
            payeeOK = true;
        } else if (msg.sender == approver) {
            if (approverOK) revert AlreadyDone();
            approverOK = true;
        } else revert Unauthorized();
        emit Approved(msg.sender);
    }

    function release() external {
        if (!payeeOK || !approverOK) revert WrongState();
        payable(payee).transfer(amount);
        emit Released(payee, amount);
    }
}

/// Attack against DualControlVuln
contract Attack_DualControl {
    DualControlVuln public target;
    constructor(DualControlVuln _t) { target = _t; }
    function attack() external {
        // drains funds with no second approval
        target.release();
    }
}



/// @title 3. Temporal Separation
/// @dev Vulnerable: no delay enforced
contract TemporalVuln {
    bytes public data;
    event Proposed(bytes data);
    event Executed(bytes data);

    function propose(bytes calldata _data) external {
        data = _data;
        emit Proposed(_data);
    }
    function execute() external {
        // immediate execution allowed
        emit Executed(data);
    }
}

/// Hardened: enforce delay between propose & execute
contract TemporalSafe {
    bytes  public data;
    uint256 public readyAt;
    uint256 public immutable delay;
    event Proposed(bytes data, uint256 readyAt);
    event Executed(bytes data);

    constructor(uint256 _delay) { delay = _delay; }

    function propose(bytes calldata _data) external {
        data    = _data;
        readyAt = block.timestamp + delay;
        emit Proposed(_data, readyAt);
    }
    function execute() external {
        if (block.timestamp < readyAt) revert TooEarly(readyAt);
        emit Executed(data);
    }
}

/// Attack against TemporalVuln
contract Attack_Temporal {
    TemporalVuln public target;
    constructor(TemporalVuln _t) { target = _t; }
    function attack(bytes calldata _d) external {
        // no delay → both steps in one tx
        target.propose(_d);
        target.execute();
    }
}



/// @title 4. Workflow Separation
/// @dev Vulnerable: can skip/reorder steps
contract WorkflowVuln {
    enum State { None, Created, Approved, Executed }
    State public state;
    event Created();
    event Approved();
    event Executed();

    function create() external {
        state = State.Created;
        emit Created();
    }
    function approve() external {
        state = State.Approved;
        emit Approved();
    }
    function execute() external {
        state = State.Executed;
        emit Executed();
    }
}

/// Hardened: three distinct roles & strict state transitions
contract WorkflowSafe {
    mapping(address=>bool) public isCreator;
    mapping(address=>bool) public isApprover;
    mapping(address=>bool) public isExecutor;

    enum State { None, Created, Approved, Executed }
    State public state;

    event Created();
    event Approved();
    event Executed();

    constructor(address creator, address approver, address executor) {
        isCreator[creator]   = true;
        isApprover[approver] = true;
        isExecutor[executor] = true;
        state = State.None;
    }

    function create() external {
        if (!isCreator[msg.sender]) revert Unauthorized();
        if (state != State.None) revert WrongState();
        state = State.Created;
        emit Created();
    }

    function approve() external {
        if (!isApprover[msg.sender]) revert Unauthorized();
        if (state != State.Created) revert WrongState();
        state = State.Approved;
        emit Approved();
    }

    function execute() external {
        if (!isExecutor[msg.sender]) revert Unauthorized();
        if (state != State.Approved) revert WrongState();
        state = State.Executed;
        emit Executed();
    }
}

/// Attack against WorkflowVuln
contract Attack_Workflow {
    WorkflowVuln public target;
    constructor(WorkflowVuln _t) { target = _t; }
    function attack() external {
        // skip create/approve → directly execute
        target.execute();
    }
}
