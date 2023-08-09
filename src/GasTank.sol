// SPDX-License-Identifier: UNLICENSED
pragma solidity >=0.8.19;

import { Enum } from "safe-contracts/contracts/common/Enum.sol";
import { SignatureDecoder } from "safe-contracts/contracts/common/SignatureDecoder.sol";
import { Safe } from "safe-contracts/contracts/Safe.sol";
import { GelatoRelayContextERC2771 } from "@gelatonetwork/relay-context/contracts/GelatoRelayContextERC2771.sol";
import { Address } from "@openzeppelin/contracts/utils/Address.sol";

contract GasTank is SignatureDecoder, GelatoRelayContextERC2771 {

    string public constant NAME = "GasTank";
    string public constant VERSION = "0.1.0";

    bytes32 public constant DOMAIN_SEPARATOR_TYPEHASH = 0x47e79534a245952e8b16893a336b85a3d9ea9fa8c573f3d803afb92a79469218;
    // keccak256(
    //     "EIP712Domain(uint256 chainId,address verifyingContract)"
    // );

    bytes32 public constant ALLOWANCE_TRANSFER_TYPEHASH = 0x80b006280932094e7cc965863eb5118dc07e5d272c6670c4a7c87299e04fceeb;
    // keccak256(
    //     "AllowanceTransfer(address safe,address token,uint96 amount,address paymentToken,uint96 payment,uint16 nonce)"
    // );

    // Safe -> Owner -> Nonce
    mapping(address => mapping(address => uint16)) public ownerNonces;

    // Safe -> Delegate -> Allowance
    mapping(address => mapping (address => mapping(address => Allowance))) public allowances;
    // Safe -> Delegate -> Tokens
    mapping(address => mapping (address => address[])) public tokens;
    // Safe -> Delegates double linked list entry points
    mapping(address => uint48) public delegatesStart;
    // Safe -> Delegates double linked list
    mapping(address => mapping (uint48 => Delegate)) public delegates;

    // We use a double linked list for the delegates. The id is the first 6 bytes.
    // To double check the address in case of collision, the address is part of the struct.
    struct Delegate {
        address delegate;
        uint48 prev;
        uint48 next;
    }

    // The allowance info is optimized to fit into one word of storage.
    struct Allowance {
        uint256 amount;
        uint256 spent;
        uint16 resetTimeMin; // Maximum reset time span is 65k minutes
        uint32 lastResetMin;
        uint16 nonce;
    }

    event AddDelegate(address indexed safe, address delegate);
    event RemoveDelegate(address indexed safe, address delegate);
    event ExecuteAllowanceTransfer(address indexed safe, address delegate, address token, address to, uint96 value, uint16 nonce);
    event PayAllowanceTransfer(address indexed safe, address delegate, address paymentToken, address paymentReceiver, uint96 payment);
    event SetAllowance(address indexed safe, address delegate, address token, uint96 allowanceAmount, uint16 resetTime);
    event ResetAllowance(address indexed safe, address delegate, address token);
    event DeleteAllowance(address indexed safe, address delegate, address token);

    error GasTank__getFeesFromSafe_wrongFeeToken();
    error GasTank__getFeesFromSafe_wrongRelayerFee();
    error GasTank__getFeesFromSafe_invalidSignature();
    error GasTank__getFeesFromSafe_invalidSigner();
    error GasTank__getFeesFromSafe_notOwner();
    error GasTank__getFeesFromDelegate_wrongFeeToken();
    error GasTank__getFeesFromDelegate_wrongRelayerFee();

// address to,
// uint256 value,
// bytes calldata data,
// Enum.Operation operation,
// uint256 safeTxGas,
// uint256 baseGas,
// uint256 gasPrice,
// address gasToken,
// address payable refundReceiver,
// bytes memory signatures
    function execTransaction(
        bool _useSafe,
        address _safe,
        bytes memory _txData,
        bytes memory _feeSignature
    ) public onlyGelatoRelayERC2771 returns (bool success) {
        // TODO - use a different Safe to pull the fees and pay to Gelato, this should be handled with delegate feature
        // from AllowanceModule

        address feeToken = _getFeeToken();
        uint256 relayerFee = _getFee();

        // validate fee using signature/delegate/owner
        if (_useSafe) {
            getFeesFromOwner(feeToken, relayerFee, _safe, _feeSignature);
        } else {
            getFeesFromDelegate(feeToken, relayerFee, _feeSignature);
        }

        bytes memory returndata = Address.functionCall(_safe, _txData);

        // Payment to Gelato
        _transferRelayFee();

        // TODO - decode return
        return true;
    }

    function getFeesFromOwner(address _feeToken, uint256 _relayerFee, address _safe, bytes memory _feeSignature) internal {
        address owner = _getMsgSender();
        (address token, uint256 maxAmount, bytes memory signature) = abi.decode(_feeSignature, (address, uint256, bytes));

        if (token !=_feeToken) revert GasTank__getFeesFromSafe_wrongFeeToken();
        if (maxAmount < _relayerFee) revert GasTank__getFeesFromSafe_wrongRelayerFee();

        // Get current state
        uint16 ownerNonce = ownerNonces[owner][_safe];
        bytes memory transferHashData = generateTransferHashData(address(_safe), _feeToken, address(this), maxAmount, address(0), 0, ownerNonce);

        // Update state
        ownerNonces[owner][_safe] = ownerNonce + 1;

        // Perform external interactions
        // Check signature
        address signer = recoverSignature(signature, transferHashData);

        if (owner != signer) revert GasTank__getFeesFromSafe_invalidSigner();
        if (!Safe(payable(_safe)).isOwner(owner)) revert GasTank__getFeesFromSafe_notOwner();

        // Transfer token
        transfer(Safe(payable(_safe)), _feeToken, payable(address(this)), _relayerFee);

        // TODO - emit
    }

    function getFeesFromDelegate(address _feeToken, uint256 _relayerFee, bytes memory _feeSignature) internal {
        address delegate = _getMsgSender();
        (address safe, address token, uint256 maxAmount, bytes memory signature) = abi.decode(_feeSignature, (address, address, uint256, bytes));

        if (token !=_feeToken) revert GasTank__getFeesFromDelegate_wrongFeeToken();
        if (maxAmount < _relayerFee) revert GasTank__getFeesFromDelegate_wrongRelayerFee();

        // Get current state
        Allowance memory allowance = getAllowance(address(safe), delegate, _feeToken);
        bytes memory transferHashData = generateTransferHashData(address(safe), _feeToken, address(this), _relayerFee, address(0), 0, allowance.nonce);

        // Update state
        allowance.nonce = allowance.nonce + 1;
        uint256 newSpent = allowance.spent + _relayerFee;
        // Check new spent amount and overflow
        require(newSpent > allowance.spent && newSpent <= allowance.amount, "newSpent > allowance.spent && newSpent <= allowance.amount");
        allowance.spent = newSpent;

        updateAllowance(address(safe), delegate, token, allowance);

        // Perform external interactions
        // Check signature
        checkSignature(delegate, signature, transferHashData, Safe(payable(safe)));

        // Transfer token
        transfer(Safe(payable(safe)), _feeToken, payable(address(this)), _relayerFee);

        // TODO - emit
    }


    /// @dev Allows to update the allowance for a specified token. This can only be done via a Safe transaction.
    /// @param delegate Delegate whose allowance should be updated.
    /// @param token Token contract address.
    /// @param allowanceAmount allowance in smallest token unit.
    /// @param resetTimeMin Time after which the allowance should reset
    /// @param resetBaseMin Time based on which the reset time should be increased
    function setAllowance(address delegate, address token, uint96 allowanceAmount, uint16 resetTimeMin, uint32 resetBaseMin)
        public
    {
        require(delegate != address(0), "delegate != address(0)");
        require(delegates[msg.sender][uint48(uint160(delegate))].delegate == delegate, "delegates[msg.sender][uint48(delegate)].delegate == delegate");
        Allowance memory allowance = getAllowance(msg.sender, delegate, token);
        if (allowance.nonce == 0) { // New token
            // Nonce should never be 0 once allowance has been activated
            allowance.nonce = 1;
            tokens[msg.sender][delegate].push(token);
        }
        // Divide by 60 to get current time in minutes
        // solium-disable-next-line security/no-block-members
        uint32 currentMin = uint32(block.timestamp / 60);
        if (resetBaseMin > 0) {
            require(resetBaseMin <= currentMin, "resetBaseMin <= currentMin");
            allowance.lastResetMin = currentMin - ((currentMin - resetBaseMin) % resetTimeMin);
        } else if (allowance.lastResetMin == 0) {
            allowance.lastResetMin = currentMin;
        }
        allowance.resetTimeMin = resetTimeMin;
        allowance.amount = allowanceAmount;
        updateAllowance(msg.sender, delegate, token, allowance);
        emit SetAllowance(msg.sender, delegate, token, allowanceAmount, resetTimeMin);
    }

    function getAllowance(address safe, address delegate, address token) private view returns (Allowance memory allowance) {
        allowance = allowances[safe][delegate][token];
        // solium-disable-next-line security/no-block-members
        uint32 currentMin = uint32(block.timestamp / 60);
        // Check if we should reset the time. We do this on load to minimize storage read/ writes
        if (allowance.resetTimeMin > 0 && allowance.lastResetMin <= currentMin - allowance.resetTimeMin) {
            allowance.spent = 0;
            // Resets happen in regular intervals and `lastResetMin` should be aligned to that
            allowance.lastResetMin = currentMin - ((currentMin - allowance.lastResetMin) % allowance.resetTimeMin);
        }
        return allowance;
    }

    function updateAllowance(address safe, address delegate, address token, Allowance memory allowance) private {
        allowances[safe][delegate][token] = allowance;
    }

    /// @dev Allows to reset the allowance for a specific delegate and token.
    /// @param delegate Delegate whose allowance should be updated.
    /// @param token Token contract address.
    function resetAllowance(address delegate, address token) public {
        Allowance memory allowance = getAllowance(msg.sender, delegate, token);
        allowance.spent = 0;
        updateAllowance(msg.sender, delegate, token, allowance);
        emit ResetAllowance(msg.sender, delegate, token);
    }

    /// @dev Allows to remove the allowance for a specific delegate and token. This will set all values except the `nonce` to 0.
    /// @param delegate Delegate whose allowance should be updated.
    /// @param token Token contract address.
    function deleteAllowance(address delegate, address token)
        public
    {
        Allowance memory allowance = getAllowance(msg.sender, delegate, token);
        allowance.amount = 0;
        allowance.spent = 0;
        allowance.resetTimeMin = 0;
        allowance.lastResetMin = 0;
        updateAllowance(msg.sender, delegate, token, allowance);
        emit DeleteAllowance(msg.sender, delegate, token);
    }

    /// @dev Returns the chain id used by this contract.
    function getChainId() public view returns (uint256) {
        return block.chainid;
    }

    /// @dev Generates the data for the transfer hash (required for signing)
    function generateTransferHashData(
        address safe,
        address token,
        address to,
        uint256 amount,
        address paymentToken,
        uint96 payment,
        uint16 nonce
    ) private view returns (bytes memory) {
        uint256 chainId = getChainId();
        bytes32 domainSeparator = keccak256(abi.encode(DOMAIN_SEPARATOR_TYPEHASH, chainId, this));
        bytes32 transferHash = keccak256(
            abi.encode(ALLOWANCE_TRANSFER_TYPEHASH, safe, token, to, amount, paymentToken, payment, nonce)
        );
        return abi.encodePacked(bytes1(0x19), bytes1(0x01), domainSeparator, transferHash);
    }

    /// @dev Generates the transfer hash that should be signed to authorize a transfer
    function generateTransferHash(
        address safe,
        address token,
        address to,
        uint96 amount,
        address paymentToken,
        uint96 payment,
        uint16 nonce
    ) public view returns (bytes32) {
        return keccak256(generateTransferHashData(
            safe, token, to, amount, paymentToken, payment, nonce
        ));
    }

    function checkSignature(address expectedDelegate, bytes memory signature, bytes memory transferHashData, Safe safe) private view {
        address signer = recoverSignature(signature, transferHashData);
        require(
            expectedDelegate == signer && delegates[address(safe)][uint48(uint160(signer))].delegate == signer,
            "expectedDelegate == signer && delegates[address(safe)][uint48(signer)].delegate == signer"
        );
    }

    // We use the same format as used for the Safe contract, except that we only support exactly 1 signature and no contract signatures.
    function recoverSignature(bytes memory signature, bytes memory transferHashData) private view returns (address owner) {
        // If there is no signature data msg.sender should be used
        if (signature.length == 0) return msg.sender;
        // Check that the provided signature data is as long as 1 encoded ecsda signature
        require(signature.length == 65, "signatures.length == 65");
        uint8 v;
        bytes32 r;
        bytes32 s;
        (v, r, s) = signatureSplit(signature, 0);
        // If v is 0 then it is a contract signature
        if (v == 0) {
            revert("Contract signatures are not supported by this module");
        } else if (v == 1) {
            // If v is 1 we also use msg.sender, this is so that we are compatible to the GnosisSafe signature scheme
            owner = msg.sender;
        } else if (v > 30) {
            // To support eth_sign and similar we adjust v and hash the transferHashData with the Ethereum message prefix before applying ecrecover
            owner = ecrecover(keccak256(abi.encodePacked("\x19Ethereum Signed Message:\n32", keccak256(transferHashData))), v - 4, r, s);
        } else {
            // Use ecrecover with the messageHash for EOA signatures
            owner = ecrecover(keccak256(transferHashData), v, r, s);
        }
        // 0 for the recovered owner indicates that an error happened.
        require(owner != address(0), "owner != address(0)");
    }

    function transfer(Safe safe, address token, address payable to, uint256 amount) private {
        if (token == address(0)) {
            // solium-disable-next-line security/no-send
            require(safe.execTransactionFromModule(to, amount, "", Enum.Operation.Call), "Could not execute ether transfer");
        } else {
            bytes memory data = abi.encodeWithSignature("transfer(address,uint256)", to, amount);
            require(safe.execTransactionFromModule(token, 0, data, Enum.Operation.Call), "Could not execute token transfer");
        }
    }

    function getTokens(address safe, address delegate) public view returns (address[] memory) {
        return tokens[safe][delegate];
    }

    function getTokenAllowance(address safe, address delegate, address token) public view returns (uint256[5] memory) {
        Allowance memory allowance = getAllowance(safe, delegate, token);
        return [
            uint256(allowance.amount),
            uint256(allowance.spent),
            uint256(allowance.resetTimeMin),
            uint256(allowance.lastResetMin),
            uint256(allowance.nonce)
        ];
    }

    /// @dev Allows to add a delegate.
    /// @param delegate Delegate that should be added.
    function addDelegate(address delegate) public {
        uint48 index = uint48(uint160(delegate));
        require(index != uint(0), "index != uint(0)");
        address currentDelegate = delegates[msg.sender][index].delegate;
        if(currentDelegate != address(0)) {
            // We have a collision for the indices of delegates
            require(currentDelegate == delegate, "currentDelegate == delegate");
            // Delegate already exists, nothing to do
            return;
        }
        uint48 startIndex = delegatesStart[msg.sender];
        delegates[msg.sender][index] = Delegate(delegate, 0, startIndex);
        delegates[msg.sender][startIndex].prev = index;
        delegatesStart[msg.sender] = index;
        emit AddDelegate(msg.sender, delegate);
    }

    /// @dev Allows to remove a delegate.
    /// @param delegate Delegate that should be removed.
    /// @param removeAllowances Indicator if allowances should also be removed. This should be set to `true` unless this causes an out of gas, in this case the allowances should be "manually" deleted via `deleteAllowance`.
    function removeDelegate(address delegate, bool removeAllowances) public {
        Delegate memory current = delegates[msg.sender][uint48(uint160(delegate))];
        // Delegate doesn't exists, nothing to do
        if(current.delegate == address(0)) return;
        if (removeAllowances) {
            address[] storage delegateTokens = tokens[msg.sender][delegate];
            for (uint256 i = 0; i < delegateTokens.length; i++) {
                address token = delegateTokens[i];
                // Set all allowance params except the nonce to 0
                Allowance memory allowance = getAllowance(msg.sender, delegate, token);
                allowance.amount = 0;
                allowance.spent = 0;
                allowance.resetTimeMin = 0;
                allowance.lastResetMin = 0;
                updateAllowance(msg.sender, delegate, token, allowance);
                emit DeleteAllowance(msg.sender, delegate, token);
            }
        }
        if (current.prev == 0) {
            delegatesStart[msg.sender] = current.next;
        } else {
            delegates[msg.sender][current.prev].next = current.next;
        }
        if (current.next != 0) {
            delegates[msg.sender][current.next].prev = current.prev;
        }
        delete delegates[msg.sender][uint48(uint160(delegate))];
        emit RemoveDelegate(msg.sender, delegate);
    }

    function getDelegates(address safe, uint48 start, uint8 pageSize) public view returns (address[] memory results, uint48 next) {
        results = new address[](pageSize);
        uint8 i = 0;
        uint48 initialIndex = (start != 0) ? start : delegatesStart[safe];
        Delegate memory current = delegates[safe][initialIndex];
        while(current.delegate != address(0) && i < pageSize) {
            results[i] = current.delegate;
            i++;
            current = delegates[safe][current.next];
        }
        next = uint48(uint160(current.delegate));
        // Set the length of the array the number that has been used.
        // solium-disable-next-line security/no-inline-assembly
        assembly {
            mstore(results, i)
        }
    }
}
