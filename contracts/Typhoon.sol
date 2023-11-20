// SPDX-License-Identifier: MIT
pragma solidity 0.8.20;

import "./MerkleTreeWithHistory.sol";
import "@openzeppelin/contracts/utils/ReentrancyGuard.sol";
import "@openzeppelin/contracts/access/Ownable.sol";

interface IDepositVerifier {
  function verifyProof(bytes memory _proof, uint256[9] memory _input) external returns (bool);
}

interface IWithdrawVerifier {
  function verifyProof(bytes memory _proof, uint256[4] memory _input) external returns (bool);
}

contract Typhoon is MerkleTreeWithHistory, ReentrancyGuard, Ownable {
  IDepositVerifier public immutable depositVerifier;
  IWithdrawVerifier public immutable withdrawVerifier;

  uint256 public denomination;
  address public blockedAddress;

  mapping(bytes32 => bool) public nullifierHashes;
  // we store all commitments just to prevent accidental deposits with the same commitment
  mapping(bytes32 => bool) public commitments;

  event BlockAddress(address indexed blocked, uint256 timestamp);
  event Deposit(bytes32 indexed commitment, uint32 leafIndex, uint256 timestamp);
  event Withdrawal(address to, bytes32 nullifierHash, address indexed relayer, uint256 fee);

  /**
    @dev The constructor
    @param _depositVerfier the address of SNARK verifier for deposit
    @param _withdrawVerifier the address of SNARK verifier for withdraw
    @param _hasher the address of MiMC hash contract
    @param _denomination transfer amount for each deposit
    @param _merkleTreeHeight the height of deposits' Merkle Tree
  */
  constructor(
    IDepositVerifier _depositVerfier,
    IWithdrawVerifier _withdrawVerifier,
    IHasher _hasher,
    uint256 _denomination,
    uint32 _merkleTreeHeight
  ) MerkleTreeWithHistory(_merkleTreeHeight, _hasher) Ownable(msg.sender) {
    require(_denomination > 0, "denomination should be greater than 0");
    depositVerifier = _depositVerfier;
    withdrawVerifier = _withdrawVerifier;
    denomination = _denomination;
  }

  /**
    @dev Deposit funds into the contract. The caller must send (for ETH) equal to or `denomination` of this instance.
    @param _proof zkSNARK proof data to prove commitment is constructed with public key from msg.sender
    @param _commitment the note commitment, which is PedersenHash(nullifier + secret)
    @param _pubkey uncompressed pubkey of sender
  */
  function deposit(bytes calldata _proof, bytes32 _commitment, bytes calldata _pubkey) external payable nonReentrant {
    require(!commitments[_commitment], "The commitment has been submitted");
    require(msg.value == denomination, "Please send `mixDenomination` ETH along with transaction");
    require(isOnCurve(uint256(bytes32(_pubkey[0:32])), uint256(bytes32(_pubkey[32: 64]))), "The public key is invalid");
    require(address(bytes20(keccak256(_pubkey[0:32]))) == msg.sender, "The pubkey is not from sender");
    require(
      depositVerifier.verifyProof(
        _proof,
        [
          uint256(bytes32(_pubkey[0:8])),
          uint256(bytes32(_pubkey[0:16])),
          uint256(bytes32(_pubkey[16:24])),
          uint256(bytes32(_pubkey[24:32])),
          uint256(bytes32(_pubkey[32:40])),
          uint256(bytes32(_pubkey[40:48])),
          uint256(bytes32(_pubkey[48:56])),
          uint256(bytes32(_pubkey[56:64])),
          uint256(_commitment)
        ]
      ),
      "The commitment is not constructed from pubkey"
    );
    uint32 insertedIndex = _insert(_commitment);
    commitments[_commitment] = true;

    emit Deposit(_commitment, insertedIndex, block.timestamp);
  }

  function withdraw(
    bytes calldata _proof,
    bytes32 _root,
    bytes32 _nullifierHash,
    address _recipient,
    uint256 _fee
  ) external payable nonReentrant {
    require(_fee <= denomination, "Fee exceeds transfer value");
    require(!nullifierHashes[_nullifierHash], "The note has been already spent");
    require(isKnownRoot(_root), "Cannot find your merkle root"); // Make sure to use a recent one
    require(msg.value == 0, "Message value is supposed to be zero for ETH instance");

    if (blockedAddress != address(0)) {
      require(
        withdrawVerifier.verifyProof(
          _proof,
          [
            uint256(_root), 
            uint256(_nullifierHash), 
            uint256(uint160(blockedAddress)),
            uint256(uint160(_recipient))
          ]
        ),
        "Invalid withdraw proof"
      );
    }
    nullifierHashes[_nullifierHash] = true;

    (bool success, ) = _recipient.call{ value: denomination - _fee }("");
    require(success, "payment to _recipient did not go thru");
    if (_fee > 0) {
      (success, ) = owner().call{ value: _fee }("");
      require(success, "payment to owner did not go thru");
    }
  }

  function lockFund(address _addr) external onlyOwner {
    blockedAddress = _addr;
    emit BlockAddress(_addr, block.timestamp);
  }

  /// @dev Check whether point (x,y) is on curve defined by a, b, and _pp.
  /// @param _x coordinate x of P1
  /// @param _y coordinate y of P1
  /// @return true if x,y in the curve, false else
  function isOnCurve(uint _x, uint _y) internal pure returns (bool) {
    uint256 AA = 0;
    uint256 BB = 7;
    uint256 PP = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F;
    
    if (0 == _x || _x >= PP || 0 == _y || _y >= PP) {
      return false;
    }
    // y^2
    uint lhs = mulmod(_y, _y, PP);
    // x^3
    uint rhs = mulmod(mulmod(_x, _x, PP), _x, PP);
    if (AA != 0) {
      // x^3 + a*x
      rhs = addmod(rhs, mulmod(_x, AA, PP), PP);
    }
    if (BB != 0) {
      // x^3 + a*x + b
      rhs = addmod(rhs, BB, PP);
    }

    return lhs == rhs;
  }
}