//SPDX-License-Identifier: Unlicense
// https://github.com/ProjectOpenSea/meta-transactions/blob/main/contracts/ERC721MetaTransactionMaticSample.sol
pragma solidity ^0.8.0;

import "@openzeppelin/contracts/token/ERC1155/ERC1155.sol";

/**
 * https://github.com/maticnetwork/pos-portal/blob/master/contracts/common/ContextMixin.sol
 */
abstract contract ContextMixin {
    function msgSender()
        internal
        view
        returns (address payable sender)
    {
        if (msg.sender == address(this)) {
            bytes memory array = msg.data;
            uint256 index = msg.data.length;
            assembly {
                // Load the 32 bytes word from memory with the address on the lower 20 bytes, and mask those.
                sender := and(
                    mload(add(array, index)),
                    0xffffffffffffffffffffffffffffffffffffffff
                )
            }
        } else {
            sender = payable(msg.sender);
        }
        return sender;
    }
}

/**
 * https://github.com/maticnetwork/pos-portal/blob/master/contracts/common/Initializable.sol
 */
contract Initializable {
    bool inited = false;

    modifier initializer() {
        require(!inited, "already inited");
        _;
        inited = true;
    }
}

/**
 * https://github.com/maticnetwork/pos-portal/blob/master/contracts/common/EIP712Base.sol
 */
contract EIP712Base is Initializable {
    struct EIP712Domain {
        string name;
        string version;
        address verifyingContract;
        bytes32 salt;
    }

    string constant public ERC712_VERSION = "1";

    bytes32 internal constant EIP712_DOMAIN_TYPEHASH = keccak256(
        bytes(
            "EIP712Domain(string name,string version,address verifyingContract,bytes32 salt)"
        )
    );
    bytes32 internal domainSeperator;

    // supposed to be called once while initializing.
    // one of the contractsa that inherits this contract follows proxy pattern
    // so it is not possible to do this in a constructor
    function _initializeEIP712(
        string memory name
    )
        internal
        initializer
    {
        _setDomainSeperator(name);
    }

    function _setDomainSeperator(string memory name) internal {
        domainSeperator = keccak256(
            abi.encode(
                EIP712_DOMAIN_TYPEHASH,
                keccak256(bytes(name)),
                keccak256(bytes(ERC712_VERSION)),
                address(this),
                bytes32(getChainId())
            )
        );
    }

    function getDomainSeperator() public view returns (bytes32) {
        return domainSeperator;
    }

    function getChainId() public view returns (uint256) {
        uint256 id;
        assembly {
            id := chainid()
        }
        return id;
    }

    /**
     * Accept message hash and returns hash message in EIP712 compatible form
     * So that it can be used to recover signer from signature signed using EIP712 formatted data
     * https://eips.ethereum.org/EIPS/eip-712
     * "\\x19" makes the encoding deterministic
     * "\\x01" is the version byte to make it compatible to EIP-191
     */
    function toTypedMessageHash(bytes32 messageHash)
        internal
        view
        returns (bytes32)
    {
        return
            keccak256(
                abi.encodePacked("\x19\x01", getDomainSeperator(), messageHash)
            );
    }
}

/**
 * https://github.com/maticnetwork/pos-portal/blob/master/contracts/common/NativeMetaTransaction.sol
 */
contract NativeMetaTransaction is EIP712Base {
    bytes32 private constant META_TRANSACTION_TYPEHASH = keccak256(
        bytes(
            "MetaTransaction(uint256 nonce,address from,bytes functionSignature)"
        )
    );
    event MetaTransactionExecuted(
        address userAddress,
        address payable relayerAddress,
        bytes functionSignature
    );
    mapping(address => uint256) nonces;

    /*
     * Meta transaction structure.
     * No point of including value field here as if user is doing value transfer then he has the funds to pay for gas
     * He should call the desired function directly in that case.
     */
    struct MetaTransaction {
        uint256 nonce;
        address from;
        bytes functionSignature;
    }

    function executeMetaTransaction(
        address userAddress,
        bytes memory functionSignature,
        bytes32 sigR,
        bytes32 sigS,
        uint8 sigV
    ) public payable returns (bytes memory) {
        MetaTransaction memory metaTx = MetaTransaction({
            nonce: nonces[userAddress],
            from: userAddress,
            functionSignature: functionSignature
        });

        require(
            verify(userAddress, metaTx, sigR, sigS, sigV),
            "Signer and signature do not match"
        );

        // increase nonce for user (to avoid re-use)
        nonces[userAddress] = nonces[userAddress] + 1;

        emit MetaTransactionExecuted(
            userAddress,
            payable(msg.sender),
            functionSignature
        );

        // Append userAddress and relayer address at the end to extract it from calling context
        (bool success, bytes memory returnData) = address(this).call(
            abi.encodePacked(functionSignature, userAddress)
        );
        require(success, "Function call not successful");

        return returnData;
    }

    function hashMetaTransaction(MetaTransaction memory metaTx)
        internal
        pure
        returns (bytes32)
    {
        return
            keccak256(
                abi.encode(
                    META_TRANSACTION_TYPEHASH,
                    metaTx.nonce,
                    metaTx.from,
                    keccak256(metaTx.functionSignature)
                )
            );
    }

    function getNonce(address user) public view returns (uint256 nonce) {
        nonce = nonces[user];
    }

    function verify(
        address signer,
        MetaTransaction memory metaTx,
        bytes32 sigR,
        bytes32 sigS,
        uint8 sigV
    ) internal view returns (bool) {
        require(signer != address(0), "NativeMetaTransaction: INVALID_SIGNER");
        return
            signer ==
            ecrecover(
                toTypedMessageHash(hashMetaTransaction(metaTx)),
                sigV,
                sigR,
                sigS
            );
    }
}

contract ERC1155MetaTransactionMatic is ERC1155, ContextMixin, NativeMetaTransaction {

    // Admin is allowed to call functions on behalf of user
    address private ADMIN;

    // Non-custodial addresses. Admin cannot transfer/burn on behalf of user
    mapping (address => bool) public hasCustody;

    // Contract name
    string public name;

    /*
    * name: Dexoshi
    * uri: https://gitlab.com/dexoshi/metadata/-/raw/main/json/{id}.json
    * uri: https://bafybeigjdnphukqz7scqwp3em5niqcupdispcjdoeqai6x2d7iypxkjexi.ipfs.nftstorage.link/{id}.json
    */
    constructor (string memory name_, string memory uri_) ERC1155(uri_) {
        name = name_;
        _initializeEIP712(name);
        ADMIN = msg.sender;
    }

    /**
     * This is used instead of msg.sender as transactions won't be sent by the original token owner, but by OpenSea.
     */
    function _msgSender()
        internal
        override
        view
        returns (address sender)
    {
        return ContextMixin.msgSender();
    }

    /**
    * As another option for supporting trading without requiring meta transactions, override isApprovedForAll to whitelist OpenSea proxy accounts on Matic
    */
    function isApprovedForAll(
        address _owner,
        address _operator
    ) public override view returns (bool isOperator) {
        if (_operator == address(0x1E0049783F008A0085193E00003D00cd54003c71)) {
            return true;
        }
        return ERC1155.isApprovedForAll(_owner, _operator);
    }

    /*
    * Optional: Converts twitter id to address https://developer.twitter.com/en/docs/twitter-ids
    * Twitter handle to twitter ID: https://www.codeofaninja.com/tools/find-twitter-id/
    * @param _twitterId twitter identifier
    * @example 1215122943765774337 returns 0x29FA969D379DB911095E7fc45133C39D24Af7eE6
    */
    function twitterIdToAddress(uint64 _twitterId) public pure returns(address) {
        return address(bytes20(sha256(abi.encodePacked(_twitterId))));
    }

       /*
    * Toggle address custody
    * @param _bool true  = user HAS          custody. Admin CANNOT move tokens. User PAYS       for gas
    * @param _bool false = user DOESN'T have custody. Admin CAN    move tokens. User DOES'T pay for gas
    * Default is false
    */
    function setCustody(bool _bool) public {
        hasCustody[tx.origin] = _bool;
    }

    /*
    * Only admin can mint
    * @param _to address to transfer to
    * @param _tokenId token identifier
    * @param _amount of tokens to mint
    * @param _tokenURI uri to metadata json object
    */
    function adminMint(address _to, uint256 _tokenId, uint256 _amount) public {
        require(msg.sender == ADMIN, "Only admin can mint");
        _mint(_to, _tokenId, _amount, "");
    }

    /*
    * Only admin with custody can transfer
    * @params _from address. Admin cannot transfer if from address has custody
    * @params _to address to transfer to
    * @params _tokenId token identifier
    * @params _amount of tokens to transfer
    */
    function adminSafeTransferFrom(address _from, address _to, uint256 _tokenId, uint256 _amount) public {
        require(msg.sender == ADMIN, "Only admin can transfer");
        require(hasCustody[_from] == false, "Admin does not have custody");
        _safeTransferFrom(_from, _to, _tokenId, _amount, "");
    }

    /*
    * Only admin with custody can batch transfer
    * @params _from address. Admin cannot transfer if from address has custody
    * @params _to address to transfer to
    * @params _tokenIds list of tokens
    * @params _amounts list of amounts
    */
    function adminSafeBatchTransferFrom(address _from, address _to, uint256[] memory _tokenIds, uint256[] memory _amounts) public {
        require(msg.sender == ADMIN, "Only admin can burn");
        require(hasCustody[_from] == false, "Admin does not have custody");
        _safeBatchTransferFrom(_from, _to, _tokenIds, _amounts, "");
    }

    /*
    * Only admin with custody can burn
    * @params _from address. Admin cannot burn if from address has custody
    * @params _tokenId token identifier
    * @params _amount of tokens to burn
    */
    function adminBurn(address _from, uint256 _tokenId, uint256 _amount) public {
        require(msg.sender == ADMIN, "Only admin can burn");
        require(hasCustody[_from] == false, "Admin does not have custody");
        _burn(_from, _tokenId, _amount);
    }
}
