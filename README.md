# Bitcoin Blockchain Viewer

This is a simple Bitcoin blockchain viewer application developed as part of the Secure Systems Development course. The application connects to a Bitcoin node, receives broadcasts of new transactions and blocks, and displays relevant information in a human-readable format.

## Features

- Connects to a Bitcoin node and receives `inv`, `block`, and `tx` messages.
- Displays the date and time a block was added to the blockchain.
- Lists the transactions in each block along with their values.
- Shows the nonce used to successfully hash the block and the difficulty level.
- Verifies that the hash matches the hash included in the block.

## Prerequisites

- Go programming language (version 1.13 or later)

## Installation

1. **Clone the repository**:
    ```sh
    git clone git@github.com:SalilLuley/ssd-assignment-3.git
    cd ssd-assignment-3
    ```

2. **Build the application**:
    ```sh
    go build -o bitcoin-viewer main.go
    ```

## Usage

Run the application using the following command:
```sh
    go run main.go
```

    OR

```sh
./bitcoin-viewer
```

The application will connect to the Bitcoin node at `seed.bitcoin.sipa.be:8333` and start receiving and displaying block and transaction information.

## Code Overview

### Main Functions

- `main()`: Entry point of the application. Establishes a connection to the Bitcoin node and starts receiving messages.
- `handleIncomingMessages(conn net.Conn)`: Continuously reads and processes incoming messages from the Bitcoin node.
- `readMessage(conn net.Conn) ([]byte, error)`: Reads a complete message from the Bitcoin node.
- `processMessage(msg []byte, conn net.Conn)`: Processes different types of messages such as `version`, `verack`, `inv`, `ping`, `tx`, `block`.
- `sendVersionMessage(conn net.Conn)`: Sends a `version` message to the Bitcoin node.
- `sendVerackMessage(conn net.Conn)`: Sends a `verack` message to the Bitcoin node.
- `sendPongMessage(conn net.Conn, payload []byte)`: Sends a `pong` message in response to a `ping` message.
- `processInvMessage(payload []byte, conn net.Conn)`: Processes an `inv` message and requests data for transactions or blocks.
- `sendGetDataMessage(conn net.Conn, invType uint32, hash [32]byte)`: Requests the full data for a given transaction or block.
- `displayBlockInfo(block []byte)`: Displays detailed information about a block.
- `displayTransactionInfo(tx []byte)`: Displays detailed information about a transaction.

### Helper Functions

- `doubleSHA256(data []byte) [32]byte`: Computes the double SHA256 hash of the given data.
- `compactToTarget(bits uint32) *big.Int`: Decodes the compact format of the difficulty target.
- `reverseBytes(data []byte) []byte`: Reverses the bytes of the given data.
- `readVarInt(buf *bytes.Reader) uint64`: Reads a variable-length integer from the buffer.
- `constructMessage(command string, payload []byte) []byte`: Constructs a message to be sent to the Bitcoin node.
- `createVersionMessage() []byte`: Creates a `version` message payload.

---

## Example: Block and Transaction Log Details

When processing a block, various details about the block and its transactions are logged. Below is an example of what these log details look like and explanations of what they mean.

### Block Details

```
Processing block message
Block Version: 538345472
Previous Block: 85a8ba7e6f5228bdcddbd573225d410697201aa83cad00000000000000000000
Merkle Root: 65c185061c295585668ea76cd8e3f75ee0990643b57c06f347cf160f9cad5438
Timestamp: Thu, 16 May 2024 16:37:16 IST
Difficulty Bits: 386097818
Nonce: 3337007718
Calculated Block Hash: 0000000000000000000168c489fedd1a05af060e7d0c8877d6c5b9f976a0b55f
Hash is valid: true
Transactions Count: 667
```

#### Explanation:

- **Block Version:** Indicates the version of the block.
- **Previous Block:** The hash of the previous block in the blockchain, linking the current block to the previous one.
- **Merkle Root:** The root of the Merkle tree, a data structure used to efficiently and securely verify the integrity of transactions.
- **Timestamp:** The time when the block was mined.
- **Difficulty Bits:** Represents the difficulty target of the block, used for mining.
- **Nonce:** A value that miners adjust to find a valid block hash.
- **Calculated Block Hash:** The hash of the block that was calculated.
- **Hash is valid:** Indicates if the calculated block hash meets the network's difficulty target.
- **Transactions Count:** The number of transactions included in the block.

### Transaction Details

Here is an example of transaction details included in the block:

```
Displaying 2 transactions only for better view of logs

Transaction 1: 9b283f08e5b59cb38aae2557342e331a51d65b03ebd0c61339ebcd41295e5000
  Input 1: Previous Tx: 0000000000000000000000000000000000000000000000000000000000000000, Index: 4294967295, Sequence: 1
  Output 1: Value: 546, Script: 76a914c6740a12d0a7d556f89782bf5faf0e12cf25a63988ac
  Output 2: Value: 364643737, Script: 76a914c85526a428126c00ad071b56341a5a553a5e96a388ac
  Output 3: Value: 0, Script: 6a24aa21a9ed2f4f5f22067ef4f58c4165b7859d8097f4a47c8a08f2b26b2467a9e24f8b1526

Transaction 2: 8937a5b69a46eaec75f329488c4967e5fae4d1942f2e376c9689e4f088575daa
  Input 1: Previous Tx: 35fc3a76b9a5d396e89505db9a62e4ccb0dbb63691bb66d13f283c9e46651077, Index: 0, Sequence: 2147483649
  Output 1: Value: 264167159, Script: 001443cf8216ab05a22d104baebbf1c682aba95c59d6
```

#### Explanation:

**Transaction Hash:**
- A unique identifier for the transaction.

**Inputs:**
- **Previous Tx (Previous Transaction):** The hash of the previous transaction that this input is using.
- **Index:** The specific output in the previous transaction being referenced.
- **Sequence:** A number indicating the order of the input within the transaction.

**Outputs:**
- **Value:** The amount of cryptocurrency assigned to the output.
- **Script Length:** The length of the script.
- **Script Public Key:** The script that specifies the conditions under which the output can be spent.

### Example with Additional Details

**Transaction Example:**

```
Transaction Version: 1
Input Count: 1
Input 0:
  Previous Output: 0c82138cf1808293555d95c1039fc9f7ea34357e50a468da900e4129bc00fb59
  Previous Index: 2
  Script Length: 23
  Script Signature: 1600140f8f95e3da7660889ef3302dfb51f9ea36f5cfd7
  Sequence: 4294967295
Output Count: 2
Output 0:
  Value: 428417
  Script Length: 22
  Script Public Key: 001466c6700654f8439013c9166df9c70c0afe6b0b7b
Output 1:
  Value: 499213967
  Script Length: 23
  Script Public Key: a91440d02c3e4f65b3a98e5e1c6287486b6b6785c04387
Lock Time: 0
```

#### Explanation:

**Transaction Version:**
- Indicates the version of the transaction.

**Input Count:**
- The number of inputs in the transaction.

**Input 0:**
- **Previous Output:** The transaction hash of the previous transaction.
- **Previous Index:** The index of the output in the previous transaction.
- **Script Length:** The length of the signature script.
- **Script Signature:** The script that proves ownership of the input.
- **Sequence:** A number used to enable replacement of the transaction in the mempool.

**Output Count:**
- The number of outputs in the transaction.

**Output 0:**
- **Value:** The amount assigned to this output.
- **Script Length:** The length of the output script.
- **Script Public Key:** The script that specifies the conditions for spending this output.

**Lock Time:**
- Indicates the earliest time or block when the transaction can be added to the blockchain.


## Documentation

For more details on the Bitcoin protocol and message formats, refer to the official [Bitcoin protocol documentation](https://en.bitcoin.it/wiki/Protocol_documentation).

## Contributions

Contributions are welcome! Please open an issue or submit a pull request for any improvements or bug fixes.

## Contact

For any questions or issues, please contact Salil at [salil.luley@gmail.com].

