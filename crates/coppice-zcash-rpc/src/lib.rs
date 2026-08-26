//! Generic zcashd-compatible JSON-RPC host adapter for Coppice.
//!
//! This crate deliberately knows only the documented JSON-RPC contract. Zakura
//! is the reference implementation used for qualification, not an API
//! dependency. RPC replies are untrusted transport: this adapter validates the
//! JSON shape and canonical linkage, and delegates all carrier and full/compact
//! transaction authentication to the existing `coppice-librustzcash` path.

#![forbid(unsafe_code)]

use std::{
    collections::BTreeMap,
    fmt::Debug,
    io::{Cursor, Read, Write},
    net::{TcpStream, ToSocketAddrs},
    time::Duration,
};

use base64::{Engine as _, engine::general_purpose::STANDARD};
use coppice_core::replay::{CoreReplayActivationCheckpoint, IronwoodFrontier};
use coppice_librustzcash::{CanonicalBlockSource, CanonicalTip, FullTransactionSource};
use serde_json::{Value, json};
use zcash_client_backend::proto::compact_formats::{CompactBlock, CompactOrchardAction, CompactTx};
use zcash_primitives::transaction::Transaction;
use zcash_protocol::{
    consensus::{BlockHeight, BranchId, NetworkType, Parameters},
    constants::MAX_BLOCK_BYTES,
};

/// An intentionally small synchronous transport boundary. Tests can inject a
/// deterministic hostile transport; production normally uses [`HttpTransport`].
pub trait RpcTransport {
    type Error: Debug;

    fn send(&mut self, request: &[u8]) -> Result<Vec<u8>, Self::Error>;
}

/// HTTP connection settings for a normal node JSON-RPC endpoint.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ZcashRpcConfig {
    /// An `http://host[:port]/path` endpoint. TLS termination may be placed in
    /// front of the adapter; the built-in transport intentionally stays small.
    pub endpoint: String,
    /// Optional HTTP basic-auth credentials used by zcashd-compatible nodes.
    pub basic_auth: Option<(String, String)>,
    /// Hard bound for one HTTP response, including JSON framing.
    pub max_response_bytes: usize,
    /// Bound connection establishment and each socket read/write. A stalled
    /// local or proxied node must fail as transport, not hold reconciliation
    /// forever.
    pub timeout: Duration,
}

impl ZcashRpcConfig {
    pub const DEFAULT_MAX_RESPONSE_BYTES: usize = MAX_BLOCK_BYTES + (MAX_BLOCK_BYTES / 2);

    pub fn new(endpoint: impl Into<String>) -> Self {
        Self {
            endpoint: endpoint.into(),
            basic_auth: None,
            max_response_bytes: Self::DEFAULT_MAX_RESPONSE_BYTES,
            timeout: Duration::from_secs(15),
        }
    }
}

#[derive(Debug)]
pub enum HttpTransportError {
    InvalidEndpoint,
    UnsupportedScheme,
    Io(std::io::Error),
    InvalidResponse,
    HttpStatus(u16),
    ResponseTooLarge { limit: usize },
}

/// Minimal HTTP/1.0 JSON-RPC transport. It supports the ordinary local
/// full-node deployment without introducing an HTTP client dependency.
pub struct HttpTransport {
    config: ZcashRpcConfig,
}

impl HttpTransport {
    pub fn new(config: ZcashRpcConfig) -> Result<Self, HttpTransportError> {
        if !config.endpoint.starts_with("http://") {
            return if config.endpoint.contains("://") {
                Err(HttpTransportError::UnsupportedScheme)
            } else {
                Err(HttpTransportError::InvalidEndpoint)
            };
        }
        if config.max_response_bytes == 0 {
            return Err(HttpTransportError::InvalidEndpoint);
        }
        Ok(Self { config })
    }

    fn authority_and_path(&self) -> Result<(&str, &str), HttpTransportError> {
        let endpoint = self.config.endpoint.strip_prefix("http://").unwrap();
        let (authority, path) = endpoint.split_once('/').unwrap_or((endpoint, ""));
        if authority.is_empty() {
            return Err(HttpTransportError::InvalidEndpoint);
        }
        Ok((
            authority,
            if path.is_empty() {
                "/"
            } else {
                &endpoint[authority.len()..]
            },
        ))
    }
}

impl RpcTransport for HttpTransport {
    type Error = HttpTransportError;

    fn send(&mut self, request: &[u8]) -> Result<Vec<u8>, Self::Error> {
        let (authority, path) = self.authority_and_path()?;
        let address = authority
            .to_socket_addrs()
            .map_err(HttpTransportError::Io)?
            .next()
            .ok_or(HttpTransportError::InvalidEndpoint)?;
        let mut stream = TcpStream::connect_timeout(&address, self.config.timeout)
            .map_err(HttpTransportError::Io)?;
        stream
            .set_read_timeout(Some(self.config.timeout))
            .and_then(|_| stream.set_write_timeout(Some(self.config.timeout)))
            .map_err(HttpTransportError::Io)?;
        let mut headers = format!(
            "POST {path} HTTP/1.0\r\nHost: {authority}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n",
            request.len()
        );
        if let Some((username, password)) = &self.config.basic_auth {
            headers.push_str("Authorization: Basic ");
            headers.push_str(&STANDARD.encode(format!("{username}:{password}")));
            headers.push_str("\r\n");
        }
        headers.push_str("\r\n");
        stream
            .write_all(headers.as_bytes())
            .and_then(|_| stream.write_all(request))
            .map_err(HttpTransportError::Io)?;

        let mut response = Vec::new();
        stream
            .take((self.config.max_response_bytes + 1) as u64)
            .read_to_end(&mut response)
            .map_err(HttpTransportError::Io)?;
        if response.len() > self.config.max_response_bytes {
            return Err(HttpTransportError::ResponseTooLarge {
                limit: self.config.max_response_bytes,
            });
        }
        let split = response
            .windows(4)
            .position(|window| window == b"\r\n\r\n")
            .ok_or(HttpTransportError::InvalidResponse)?;
        let header = std::str::from_utf8(&response[..split])
            .map_err(|_| HttpTransportError::InvalidResponse)?;
        let status = header
            .lines()
            .next()
            .and_then(|line| line.split_whitespace().nth(1))
            .and_then(|code| code.parse::<u16>().ok())
            .ok_or(HttpTransportError::InvalidResponse)?;
        if status != 200 {
            return Err(HttpTransportError::HttpStatus(status));
        }
        Ok(response[(split + 4)..].to_vec())
    }
}

#[derive(Debug)]
pub enum RpcError<E: Debug> {
    Transport(E),
    Json(serde_json::Error),
    MalformedResponse(&'static str),
    Server {
        code: Option<i64>,
        message: String,
    },
    InvalidHash {
        field: &'static str,
    },
    InvalidHeight {
        field: &'static str,
    },
    NetworkMismatch {
        expected: &'static str,
        actual: String,
    },
    InconsistentTip,
    RequiredHistoryPruned {
        required_from: u32,
        available_from: u32,
    },
    MissingCanonicalBlock {
        height: u32,
    },
    WrongBlockHash {
        requested: [u8; 32],
        received: [u8; 32],
    },
    WrongBlockHeight {
        requested: u32,
        received: u32,
    },
    MissingPreviousBlockHash {
        height: u32,
    },
    InvalidTransactionId {
        index: usize,
    },
    MissingTransaction {
        txid: [u8; 32],
    },
    InvalidTransactionHex {
        txid: [u8; 32],
    },
    TransactionTooLarge {
        txid: [u8; 32],
        len: usize,
        limit: usize,
    },
    BlockTransactionBudgetExceeded {
        attempted: usize,
        limit: usize,
    },
    TransactionParse {
        txid: [u8; 32],
    },
    TransactionIdMismatch {
        expected: [u8; 32],
        actual: [u8; 32],
    },
    TooManyTransactions,
    InvalidIronwoodAction {
        txid: [u8; 32],
    },
    CacheMiss {
        txid: [u8; 32],
    },
    MissingIronwoodTreeState {
        height: u32,
    },
    InvalidIronwoodTreeState {
        height: u32,
    },
    IronwoodRootMismatch {
        height: u32,
    },
    CanonicalHistoryChanged {
        height: u32,
    },
}

/// Narrow JSON-RPC client; it exposes only the methods this adapter needs.
pub struct ZcashRpcClient<T> {
    transport: T,
    next_id: u64,
}

impl<T> ZcashRpcClient<T> {
    pub fn new(transport: T) -> Self {
        Self {
            transport,
            next_id: 1,
        }
    }

    pub fn into_transport(self) -> T {
        self.transport
    }
}

impl<T: RpcTransport> ZcashRpcClient<T> {
    fn call(&mut self, method: &'static str, params: Value) -> Result<Value, RpcError<T::Error>> {
        let id = self.next_id;
        self.next_id = self
            .next_id
            .checked_add(1)
            .ok_or(RpcError::MalformedResponse("request id overflow"))?;
        let request = serde_json::to_vec(
            &json!({"jsonrpc":"1.0", "id":id, "method":method, "params":params}),
        )
        .map_err(RpcError::Json)?;
        let bytes = self.transport.send(&request).map_err(RpcError::Transport)?;
        let response: Value = serde_json::from_slice(&bytes).map_err(RpcError::Json)?;
        let object = response
            .as_object()
            .ok_or(RpcError::MalformedResponse("response is not an object"))?;
        if object.get("id").and_then(Value::as_u64) != Some(id) {
            return Err(RpcError::MalformedResponse("response id mismatch"));
        }
        if let Some(error) = object.get("error")
            && !error.is_null()
        {
            let error_object = error
                .as_object()
                .ok_or(RpcError::MalformedResponse("error is not an object"))?;
            let message = error_object
                .get("message")
                .and_then(Value::as_str)
                .ok_or(RpcError::MalformedResponse("error message"))?;
            return Err(RpcError::Server {
                code: error_object.get("code").and_then(Value::as_i64),
                message: message.to_owned(),
            });
        }
        object
            .get("result")
            .cloned()
            .ok_or(RpcError::MalformedResponse("missing result"))
    }

    fn get_blockchain_info(&mut self) -> Result<Value, RpcError<T::Error>> {
        self.call("getblockchaininfo", json!([]))
    }

    fn get_block_count(&mut self) -> Result<u32, RpcError<T::Error>> {
        number_u32(&self.call("getblockcount", json!([]))?, "getblockcount")
    }

    fn get_best_block_hash(&mut self) -> Result<[u8; 32], RpcError<T::Error>> {
        rpc_hash(
            &self.call("getbestblockhash", json!([]))?,
            "getbestblockhash",
        )
    }

    fn get_block_hash(&mut self, height: u32) -> Result<[u8; 32], RpcError<T::Error>> {
        rpc_hash(&self.call("getblockhash", json!([height]))?, "getblockhash")
    }

    fn get_block(&mut self, hash: [u8; 32]) -> Result<Value, RpcError<T::Error>> {
        self.call("getblock", json!([display_hash(hash), 1]))
    }

    fn get_raw_transaction(
        &mut self,
        txid: [u8; 32],
        block_hash: [u8; 32],
    ) -> Result<Option<Vec<u8>>, RpcError<T::Error>> {
        match self.call(
            "getrawtransaction",
            json!([display_hash(txid), 0, display_hash(block_hash)]),
        ) {
            Ok(value) => {
                let encoded = value
                    .as_str()
                    .ok_or(RpcError::MalformedResponse("getrawtransaction result"))?;
                let bytes =
                    hex::decode(encoded).map_err(|_| RpcError::InvalidTransactionHex { txid })?;
                Ok(Some(bytes))
            }
            Err(RpcError::Server { code: Some(-5), .. }) => Ok(None),
            Err(error) => Err(error),
        }
    }

    /// Submits already-authorized bytes. It never constructs a transaction or
    /// invokes node wallet functionality.
    pub fn submit_raw_transaction(&mut self, bytes: &[u8]) -> Result<[u8; 32], RpcError<T::Error>> {
        if bytes.len() > MAX_BLOCK_BYTES {
            return Err(RpcError::TransactionTooLarge {
                txid: [0; 32],
                len: bytes.len(),
                limit: MAX_BLOCK_BYTES,
            });
        }
        rpc_hash(
            &self.call("sendrawtransaction", json!([hex::encode(bytes)]))?,
            "sendrawtransaction",
        )
    }
}

/// Host-specific operational constraints, not protocol identity.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RpcAdapterConfig {
    /// Network label expected from `getblockchaininfo`.
    pub expected_network: NetworkType,
    /// Earliest canonical block body required for activation/rebuild.
    pub required_history_from: u32,
}

impl RpcAdapterConfig {
    pub const fn new(expected_network: NetworkType, required_history_from: u32) -> Self {
        Self {
            expected_network,
            required_history_from,
        }
    }
}

/// RPC-backed canonical block source. A block-local raw-byte cache lets the
/// shared CompactBlock adapter make its frozen acquisition decision without
/// duplicate RPC calls or accidental exposure of unselected transaction bytes.
pub struct RpcCanonicalBlockSource<P, T> {
    parameters: P,
    client: ZcashRpcClient<T>,
    config: RpcAdapterConfig,
    cached_transactions: BTreeMap<[u8; 32], Vec<u8>>,
}

impl<P, T> RpcCanonicalBlockSource<P, T> {
    pub fn new(parameters: P, client: ZcashRpcClient<T>, config: RpcAdapterConfig) -> Self {
        Self {
            parameters,
            client,
            config,
            cached_transactions: BTreeMap::new(),
        }
    }

    pub fn client_mut(&mut self) -> &mut ZcashRpcClient<T> {
        &mut self.client
    }

    pub fn into_client(self) -> ZcashRpcClient<T> {
        self.client
    }
}

impl<P: Parameters, T: RpcTransport> RpcCanonicalBlockSource<P, T> {
    fn check_chain_info(&mut self) -> Result<(u32, [u8; 32]), RpcError<T::Error>> {
        let info = self.client.get_blockchain_info()?;
        let object = info
            .as_object()
            .ok_or(RpcError::MalformedResponse("getblockchaininfo result"))?;
        let chain = object
            .get("chain")
            .and_then(Value::as_str)
            .ok_or(RpcError::MalformedResponse("getblockchaininfo chain"))?;
        let expected = network_name(self.config.expected_network);
        if chain != expected {
            return Err(RpcError::NetworkMismatch {
                expected,
                actual: chain.to_owned(),
            });
        }
        let info_height = number_u32(
            object
                .get("blocks")
                .ok_or(RpcError::MalformedResponse("getblockchaininfo blocks"))?,
            "blocks",
        )?;
        let info_hash = rpc_hash(
            object
                .get("bestblockhash")
                .ok_or(RpcError::MalformedResponse(
                    "getblockchaininfo bestblockhash",
                ))?,
            "bestblockhash",
        )?;
        if object.get("pruned").and_then(Value::as_bool) == Some(true) {
            let available = number_u32(
                object
                    .get("pruneheight")
                    .ok_or(RpcError::MalformedResponse("pruneheight"))?,
                "pruneheight",
            )?;
            if self.config.required_history_from != 0
                && self.config.required_history_from < available
            {
                return Err(RpcError::RequiredHistoryPruned {
                    required_from: self.config.required_history_from,
                    available_from: available,
                });
            }
        }
        let count = self.client.get_block_count()?;
        let best = self.client.get_best_block_hash()?;
        if count != info_height || best != info_hash {
            return Err(RpcError::InconsistentTip);
        }
        Ok((count, best))
    }

    /// Obtains the exact pre-activation state required by frozen Core. The
    /// `z_gettreestate` finalState uses the same commitment-tree serialization
    /// as librustzcash, and its root, height, and hash are all cross-checked.
    pub fn activation_checkpoint(
        &mut self,
        activation_height: u32,
    ) -> Result<CoreReplayActivationCheckpoint, RpcError<T::Error>> {
        let height = activation_height
            .checked_sub(1)
            .ok_or(RpcError::InvalidHeight {
                field: "activation height",
            })?;
        let expected_hash = self.client.get_block_hash(height)?;
        let result = self
            .client
            .call("z_gettreestate", json!([display_hash(expected_hash)]))?;
        let object = result
            .as_object()
            .ok_or(RpcError::MalformedResponse("z_gettreestate result"))?;
        let response_height = number_u32(
            object
                .get("height")
                .ok_or(RpcError::MalformedResponse("z_gettreestate height"))?,
            "z_gettreestate height",
        )?;
        if response_height != height {
            return Err(RpcError::WrongBlockHeight {
                requested: height,
                received: response_height,
            });
        }
        let response_hash = rpc_hash(
            object
                .get("hash")
                .ok_or(RpcError::MalformedResponse("z_gettreestate hash"))?,
            "z_gettreestate hash",
        )?;
        if response_hash != expected_hash {
            return Err(RpcError::WrongBlockHash {
                requested: expected_hash,
                received: response_hash,
            });
        }
        let commitments = object
            .get("ironwood")
            .and_then(Value::as_object)
            .and_then(|tree| tree.get("commitments"))
            .and_then(Value::as_object)
            .ok_or(RpcError::MissingIronwoodTreeState { height })?;
        let state = commitments
            .get("finalState")
            .and_then(Value::as_str)
            .ok_or(RpcError::MissingIronwoodTreeState { height })?;
        let root = commitments
            .get("finalRoot")
            .and_then(Value::as_str)
            .ok_or(RpcError::MissingIronwoodTreeState { height })?;
        let state =
            hex::decode(state).map_err(|_| RpcError::InvalidIronwoodTreeState { height })?;
        let mut cursor = Cursor::new(state);
        let frontier: IronwoodFrontier =
            zcash_primitives::merkle_tree::read_commitment_tree(&mut cursor)
                .map_err(|_| RpcError::InvalidIronwoodTreeState { height })?;
        if cursor.position() != cursor.get_ref().len() as u64 {
            return Err(RpcError::InvalidIronwoodTreeState { height });
        }
        // Commitment-tree roots are RPC hex bytes, unlike block and
        // transaction identifiers which use display-order reversal.
        let expected_root = raw_hex_32(root, "ironwood finalRoot")?;
        if frontier.root().to_bytes() != expected_root {
            return Err(RpcError::IronwoodRootMismatch { height });
        }
        if self.client.get_block_hash(height)? != expected_hash {
            return Err(RpcError::CanonicalHistoryChanged { height });
        }
        let tree_size = u32::try_from(frontier.size())
            .map_err(|_| RpcError::InvalidIronwoodTreeState { height })?;
        Ok(CoreReplayActivationCheckpoint {
            height,
            block_hash: expected_hash,
            ironwood_frontier: frontier,
            ironwood_tree_size: tree_size,
        })
    }

    fn compact_block_at(&mut self, height: u32) -> Result<CompactBlock, RpcError<T::Error>> {
        let hash = self.client.get_block_hash(height)?;
        let result = self.client.get_block(hash)?;
        let object = result
            .as_object()
            .ok_or(RpcError::MalformedResponse("getblock result"))?;
        let response_hash = rpc_hash(
            object
                .get("hash")
                .ok_or(RpcError::MalformedResponse("getblock hash"))?,
            "getblock hash",
        )?;
        if response_hash != hash {
            return Err(RpcError::WrongBlockHash {
                requested: hash,
                received: response_hash,
            });
        }
        let response_height = number_u32(
            object
                .get("height")
                .ok_or(RpcError::MalformedResponse("getblock height"))?,
            "getblock height",
        )?;
        if response_height != height {
            return Err(RpcError::WrongBlockHeight {
                requested: height,
                received: response_height,
            });
        }
        let prev_hash = rpc_hash(
            object
                .get("previousblockhash")
                .ok_or(RpcError::MissingPreviousBlockHash { height })?,
            "previousblockhash",
        )?;
        let txids = object
            .get("tx")
            .and_then(Value::as_array)
            .ok_or(RpcError::MalformedResponse("getblock tx"))?;
        if txids.len() > u32::MAX as usize {
            return Err(RpcError::TooManyTransactions);
        }
        self.cached_transactions.clear();
        let mut transactions = Vec::with_capacity(txids.len());
        let mut total_transaction_bytes = 0usize;
        for (index, value) in txids.iter().enumerate() {
            let txid = rpc_hash::<T::Error>(value, "getblock txid")
                .map_err(|_| RpcError::InvalidTransactionId { index })?;
            let bytes = self
                .client
                .get_raw_transaction(txid, hash)?
                .ok_or(RpcError::MissingTransaction { txid })?;
            if bytes.len() > MAX_BLOCK_BYTES {
                return Err(RpcError::TransactionTooLarge {
                    txid,
                    len: bytes.len(),
                    limit: MAX_BLOCK_BYTES,
                });
            }
            total_transaction_bytes = total_transaction_bytes.checked_add(bytes.len()).ok_or(
                RpcError::BlockTransactionBudgetExceeded {
                    attempted: usize::MAX,
                    limit: MAX_BLOCK_BYTES,
                },
            )?;
            if total_transaction_bytes > MAX_BLOCK_BYTES {
                return Err(RpcError::BlockTransactionBudgetExceeded {
                    attempted: total_transaction_bytes,
                    limit: MAX_BLOCK_BYTES,
                });
            }
            let branch = BranchId::for_height(&self.parameters, BlockHeight::from_u32(height));
            let mut cursor = Cursor::new(bytes.as_slice());
            let transaction = Transaction::read(&mut cursor, branch)
                .map_err(|_| RpcError::TransactionParse { txid })?;
            if cursor.position() != bytes.len() as u64 {
                return Err(RpcError::TransactionParse { txid });
            }
            let parsed_txid: [u8; 32] = transaction.txid().into();
            if parsed_txid != txid {
                return Err(RpcError::TransactionIdMismatch {
                    expected: txid,
                    actual: parsed_txid,
                });
            }
            let mut actions = Vec::new();
            if let Some(bundle) = transaction.ironwood_bundle() {
                actions.reserve(bundle.actions().len());
                for action in bundle.actions() {
                    actions.push(CompactOrchardAction {
                        nullifier: action.nullifier().to_bytes().to_vec(),
                        cmx: action.cmx().to_bytes().to_vec(),
                        ephemeral_key: action.encrypted_note().epk_bytes.to_vec(),
                        ciphertext: action.encrypted_note().enc_ciphertext[..52].to_vec(),
                    });
                }
            }
            self.cached_transactions.insert(txid, bytes);
            transactions.push(CompactTx {
                index: index as u64,
                txid: txid.to_vec(),
                ironwood_actions: actions,
                ..Default::default()
            });
        }
        // Re-check the canonical mapping for the requested height, preventing
        // a reorg from stitching a block body to a replaced height mapping.
        if self.client.get_block_hash(height)? != hash {
            self.cached_transactions.clear();
            return Err(RpcError::CanonicalHistoryChanged { height });
        }
        Ok(CompactBlock {
            height: u64::from(height),
            hash: hash.to_vec(),
            prev_hash: prev_hash.to_vec(),
            vtx: transactions,
            ..Default::default()
        })
    }
}

impl<P: Parameters, T: RpcTransport> CanonicalBlockSource for RpcCanonicalBlockSource<P, T> {
    type Error = RpcError<T::Error>;

    fn canonical_tip(&mut self) -> Result<CanonicalTip, Self::Error> {
        let (height, block_hash) = self.check_chain_info()?;
        Ok(CanonicalTip { height, block_hash })
    }

    fn compact_block(&mut self, height: u32) -> Result<Option<CompactBlock>, Self::Error> {
        self.compact_block_at(height).map(Some)
    }
}

impl<P, T: RpcTransport> FullTransactionSource for RpcCanonicalBlockSource<P, T> {
    type Error = RpcError<T::Error>;

    fn full_transaction(&mut self, txid: [u8; 32]) -> Result<Option<Vec<u8>>, Self::Error> {
        Ok(self.cached_transactions.get(&txid).cloned())
    }
}

fn network_name(network: NetworkType) -> &'static str {
    match network {
        NetworkType::Main => "main",
        NetworkType::Test => "test",
        // zcashd-compatible `getblockchaininfo` uses the historical BIP70
        // `test` label for both testnet and Regtest. The configured consensus
        // parameters, not this display label, select the local network.
        NetworkType::Regtest => "test",
    }
}

fn number_u32<E: Debug>(value: &Value, field: &'static str) -> Result<u32, RpcError<E>> {
    value
        .as_u64()
        .and_then(|number| u32::try_from(number).ok())
        .ok_or(RpcError::InvalidHeight { field })
}

/// RPC displays hashes in reverse/internal-byte order. CompactBlock and
/// librustzcash txids use wire/internal order, so conversion happens only at
/// this transport boundary.
fn rpc_hash<E: Debug>(value: &Value, field: &'static str) -> Result<[u8; 32], RpcError<E>> {
    let encoded = value.as_str().ok_or(RpcError::InvalidHash { field })?;
    let mut bytes = raw_hex_32(encoded, field)?;
    bytes.reverse();
    Ok(bytes)
}

fn raw_hex_32<E: Debug>(encoded: &str, field: &'static str) -> Result<[u8; 32], RpcError<E>> {
    hex::decode(encoded)
        .ok()
        .and_then(|bytes| bytes.try_into().ok())
        .ok_or(RpcError::InvalidHash { field })
}

fn display_hash(mut hash: [u8; 32]) -> String {
    hash.reverse();
    hex::encode(hash)
}

#[cfg(test)]
mod tests {
    use std::collections::VecDeque;

    use super::*;
    use zcash_primitives::transaction::{Authorized, TransactionData};
    use zcash_protocol::{consensus::BlockHeight, local_consensus::LocalNetwork};

    #[derive(Debug)]
    struct FakeError;

    struct FakeTransport(VecDeque<Vec<u8>>);

    impl RpcTransport for FakeTransport {
        type Error = FakeError;
        fn send(&mut self, _request: &[u8]) -> Result<Vec<u8>, Self::Error> {
            self.0.pop_front().ok_or(FakeError)
        }
    }

    fn response(id: u64, result: Value) -> Vec<u8> {
        serde_json::to_vec(&json!({"jsonrpc":"1.0", "id":id, "result":result, "error":null}))
            .unwrap()
    }

    fn params() -> LocalNetwork {
        let active = Some(BlockHeight::from_u32(1));
        LocalNetwork {
            overwinter: active,
            sapling: active,
            blossom: active,
            heartwood: active,
            canopy: active,
            nu5: active,
            nu6: active,
            nu6_1: active,
            nu6_2: active,
            nu6_3: active,
        }
    }

    fn empty_v6_transaction() -> (Vec<u8>, [u8; 32]) {
        let transaction = TransactionData::<Authorized>::from_parts_v6(
            BranchId::Nu6_3,
            0,
            BlockHeight::from_u32(10),
            None,
            None,
            None,
            None,
        )
        .freeze()
        .unwrap();
        let txid = transaction.txid().into();
        let mut bytes = Vec::new();
        transaction.write(&mut bytes).unwrap();
        (bytes, txid)
    }

    fn block_object(hash: [u8; 32], height: u32, prev: [u8; 32], txids: Vec<[u8; 32]>) -> Value {
        json!({
            "hash": display_hash(hash),
            "height": height,
            "previousblockhash": display_hash(prev),
            "tx": txids.into_iter().map(display_hash).collect::<Vec<_>>(),
        })
    }

    #[test]
    fn rpc_hash_uses_internal_byte_order() {
        let value = Value::String(
            "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f".into(),
        );
        let hash = rpc_hash::<FakeError>(&value, "hash").unwrap();
        assert_eq!(hash[0], 31);
        assert_eq!(display_hash(hash), value.as_str().unwrap());
    }

    #[test]
    fn rejects_malformed_success_body() {
        let transport = FakeTransport(VecDeque::from([br#"{\"id\":1,\"result\":[]}"#.to_vec()]));
        let mut client = ZcashRpcClient::new(transport);
        assert!(matches!(client.get_block_count(), Err(RpcError::Json(_))));
    }

    #[test]
    fn rejects_wrong_result_type() {
        let transport = FakeTransport(VecDeque::from([response(
            1,
            Value::String("not-a-count".into()),
        )]));
        let mut client = ZcashRpcClient::new(transport);
        assert!(matches!(
            client.get_block_count(),
            Err(RpcError::InvalidHeight { .. })
        ));
    }

    #[test]
    fn rejects_response_id_mismatch() {
        let transport = FakeTransport(VecDeque::from([response(2, json!(7))]));
        let mut client = ZcashRpcClient::new(transport);
        assert!(matches!(
            client.get_block_count(),
            Err(RpcError::MalformedResponse("response id mismatch"))
        ));
    }

    #[test]
    fn server_not_found_is_distinguished_for_block_scoped_transaction() {
        let transport = FakeTransport(VecDeque::from([serde_json::to_vec(&json!({
            "jsonrpc":"1.0", "id":1, "result":null,
            "error":{"code":-5,"message":"No such mempool or blockchain transaction"}
        }))
        .unwrap()]));
        let mut client = ZcashRpcClient::new(transport);
        assert_eq!(client.get_raw_transaction([1; 32], [2; 32]).unwrap(), None);
    }

    #[test]
    fn reconstructs_compact_facts_and_retains_block_scoped_raw_bytes() {
        let height = 10;
        let hash = [7; 32];
        let prev = [6; 32];
        let (bytes, txid) = empty_v6_transaction();
        let transport = FakeTransport(VecDeque::from([
            response(1, Value::String(display_hash(hash))),
            response(2, block_object(hash, height, prev, vec![txid])),
            response(3, Value::String(hex::encode(&bytes))),
            response(4, Value::String(display_hash(hash))),
        ]));
        let mut source = RpcCanonicalBlockSource::new(
            params(),
            ZcashRpcClient::new(transport),
            RpcAdapterConfig::new(NetworkType::Regtest, height),
        );
        let block = source.compact_block(height).unwrap().unwrap();
        assert_eq!(block.hash, hash);
        assert_eq!(block.prev_hash, prev);
        assert_eq!(block.vtx.len(), 1);
        assert_eq!(block.vtx[0].txid, txid);
        assert_eq!(source.full_transaction(txid).unwrap(), Some(bytes));
    }

    #[test]
    fn rejects_wrong_returned_block_height() {
        let hash = [7; 32];
        let transport = FakeTransport(VecDeque::from([
            response(1, Value::String(display_hash(hash))),
            response(2, block_object(hash, 11, [6; 32], vec![])),
        ]));
        let mut source = RpcCanonicalBlockSource::new(
            params(),
            ZcashRpcClient::new(transport),
            RpcAdapterConfig::new(NetworkType::Regtest, 10),
        );
        assert!(matches!(
            source.compact_block(10),
            Err(RpcError::WrongBlockHeight { .. })
        ));
    }

    #[test]
    fn rejects_height_mapping_changed_during_fetch() {
        let hash = [7; 32];
        let changed = [8; 32];
        let transport = FakeTransport(VecDeque::from([
            response(1, Value::String(display_hash(hash))),
            response(2, block_object(hash, 10, [6; 32], vec![])),
            response(3, Value::String(display_hash(changed))),
        ]));
        let mut source = RpcCanonicalBlockSource::new(
            params(),
            ZcashRpcClient::new(transport),
            RpcAdapterConfig::new(NetworkType::Regtest, 10),
        );
        assert!(matches!(
            source.compact_block(10),
            Err(RpcError::CanonicalHistoryChanged { height: 10 })
        ));
    }

    #[test]
    fn rejects_required_pruned_history_before_reconciliation() {
        let hash = display_hash([7; 32]);
        let transport = FakeTransport(VecDeque::from([response(
            1,
            json!({
                "chain":"test", "blocks":10, "bestblockhash":hash,
                "pruned":true, "pruneheight":9,
            }),
        )]));
        let mut source = RpcCanonicalBlockSource::new(
            params(),
            ZcashRpcClient::new(transport),
            RpcAdapterConfig::new(NetworkType::Regtest, 8),
        );
        assert!(matches!(
            source.canonical_tip(),
            Err(RpcError::RequiredHistoryPruned {
                required_from: 8,
                available_from: 9,
            })
        ));
    }
}
