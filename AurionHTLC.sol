// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

/// @notice UNAUDITED, NOT DEPLOYED. Experimental native-ETH swap leg only.
/// @dev Aurion is a separate chain; this contract does not issue or wrap AUR.
contract AurionHTLC {
    enum State { Unknown, Open, Claimed, Refunded }

    struct Swap {
        address payable sender;
        address payable recipient;
        bytes32 hashlock;
        uint64 expiresAt;
        uint256 amount;
        State state;
    }

    mapping(bytes32 => Swap) public swaps;
    mapping(address => uint256) public nonces;
    uint256 public constant MAX_LOCK_DURATION = 30 days;
    bool private entered;

    error ReentrantCall();
    error InvalidRecipient();
    error InvalidAmount();
    error InvalidHashlock();
    error InvalidDeadline();
    error SwapNotOpen();
    error NotRecipient();
    error NotSender();
    error ClaimExpired();
    error RefundTooEarly();
    error InvalidPreimage();
    error TransferFailed();

    event Locked(bytes32 indexed id, address indexed sender, address indexed recipient,
                 bytes32 hashlock, uint64 expiresAt, uint256 amount, uint256 nonce);
    event Claimed(bytes32 indexed id, bytes32 preimage, uint256 amount);
    event Refunded(bytes32 indexed id, uint256 amount);

    modifier nonReentrant() {
        if (entered) revert ReentrantCall();
        entered = true;
        _;
        entered = false;
    }

    /// @notice Lock native ETH for a fixed recipient and SHA-256 commitment.
    /// @param expiresAt Absolute Unix timestamp; no more than 30 days ahead.
    /// @return id Unique within this contract and Ethereum chain.
    function lock(address payable recipient, bytes32 hashlock, uint64 expiresAt)
        external payable nonReentrant returns (bytes32 id)
    {
        if (recipient == address(0) || recipient == address(this)) revert InvalidRecipient();
        if (msg.value == 0) revert InvalidAmount();
        if (hashlock == bytes32(0)) revert InvalidHashlock();
        if (expiresAt <= block.timestamp || uint256(expiresAt) > block.timestamp + MAX_LOCK_DURATION)
            revert InvalidDeadline();

        uint256 nonce = nonces[msg.sender]++;
        id = keccak256(abi.encode(block.chainid, address(this), msg.sender, nonce,
                                  recipient, hashlock, expiresAt, msg.value));
        swaps[id] = Swap(payable(msg.sender), recipient, hashlock, expiresAt, msg.value, State.Open);
        emit Locked(id, msg.sender, recipient, hashlock, expiresAt, msg.value, nonce);
    }

    /// @notice Only the fixed recipient can reveal the exact 32-byte preimage.
    /// @dev Revelation becomes public in transaction calldata and this event.
    function claim(bytes32 id, bytes32 preimage) external nonReentrant {
        Swap storage swap = swaps[id];
        if (swap.state != State.Open) revert SwapNotOpen();
        if (msg.sender != swap.recipient) revert NotRecipient();
        if (block.timestamp >= swap.expiresAt) revert ClaimExpired();
        if (sha256(abi.encodePacked(preimage)) != swap.hashlock) revert InvalidPreimage();

        // Effects precede the call; a failed call reverts all changes and events.
        swap.state = State.Claimed;
        emit Claimed(id, preimage, swap.amount);
        (bool success, ) = swap.recipient.call{value: swap.amount}("");
        if (!success) revert TransferFailed();
    }

    /// @notice Only the original sender can refund at/after the absolute deadline.
    function refund(bytes32 id) external nonReentrant {
        Swap storage swap = swaps[id];
        if (swap.state != State.Open) revert SwapNotOpen();
        if (msg.sender != swap.sender) revert NotSender();
        if (block.timestamp < swap.expiresAt) revert RefundTooEarly();

        swap.state = State.Refunded;
        emit Refunded(id, swap.amount);
        (bool success, ) = swap.sender.call{value: swap.amount}("");
        if (!success) revert TransferFailed();
    }
}
