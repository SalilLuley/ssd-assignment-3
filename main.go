package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"io"
	"math/big"
	"net"
	"time"
)

type TxOutput struct {
	Value        uint64
	ScriptPubKey []byte
}

type TxInput struct {
	PrevTx    []byte
	PrevIndex uint32
	ScriptSig []byte
	Sequence  uint32
}

type Transaction struct {
	Version  uint32
	Inputs   []TxInput
	Outputs  []TxOutput
	LockTime uint32
	Hash     [32]byte
}

const (
	nodeAddr   = "seed.bitcoin.sipa.be:8333"
	magicBytes = "\xf9\xbe\xb4\xd9"
)

// doubleSHA256 calculates the double SHA256 hash of the given data.
// It first calculates the SHA256 hash of the data, and then calculates
// the SHA256 hash of the resulting hash.
// The final hash is returned as a fixed-size array of 32 bytes.
func doubleSHA256(data []byte) [32]byte {
	first := sha256.Sum256(data)
	return sha256.Sum256(first[:])
}

// handleIncomingMessages reads incoming messages from the provided connection and processes them.
// It continues reading messages until an error occurs or the connection is closed by the peer.
func handleIncomingMessages(conn net.Conn) {
	for {
		msg, err := readMessage(conn)
		if err != nil {
			if err == io.EOF {
				fmt.Println("Connection closed by peer")
				break
			}
			fmt.Println("Error reading message:", err)
			break
		}
		if msg != nil {
			processMessage(msg, conn)
		}
	}
}

// readMessage reads a message from the provided network connection.
// It expects the message to have a specific format, including a header and payload.
// The function returns the complete message as a byte slice if successful, along with nil error.
// If any error occurs during reading or if the message format is invalid, an error is returned.
func readMessage(conn net.Conn) ([]byte, error) {
	header := make([]byte, 24)
	_, err := io.ReadFull(conn, header)
	if err != nil {
		return nil, fmt.Errorf("error reading header: %v", err)
	}

	if !bytes.Equal(header[:4], []byte(magicBytes)) {
		return nil, fmt.Errorf("invalid magic bytes: %x", header[:4])
	}

	length := binary.LittleEndian.Uint32(header[16:20])
	checksum := header[20:24]

	if length > 1<<24 { // Length should not be more than 16MB
		return nil, fmt.Errorf("payload length too large: %d", length)
	}

	payload := make([]byte, length)
	_, err = io.ReadFull(conn, payload)
	if err != nil {
		return nil, fmt.Errorf("error reading payload: %v", err)
	}

	actualChecksum := doubleSHA256(payload)
	if !bytes.Equal(checksum, actualChecksum[:4]) {
		return nil, fmt.Errorf("invalid checksum")
	}

	return append(header, payload...), nil
}

// processMessage processes the incoming message received from the network connection.
// It expects the message to be in byte array format and the network connection to be established.
// If the message length is less than 24 bytes, it prints an error message and returns.
// It extracts the command and payload from the message and performs different actions based on the command.
// The supported commands are: version, verack, inv, ping, tx, block, sendcmpct, getheaders, and feefilter.
// For each command, it prints a corresponding processing message and performs the necessary actions.
// If the command is unknown, it prints a message indicating that an unknown message was received.
func processMessage(msg []byte, conn net.Conn) {
	if len(msg) < 24 {
		fmt.Println("Received message too short:", msg)
		return
	}

	command := string(bytes.TrimRight(msg[4:16], "\x00"))
	payload := msg[24:]

	fmt.Printf("Received message: command=%s, length=%d\n", command, len(payload))

	switch command {
	case "version":
		fmt.Println("Processing version message")
		sendVerackMessage(conn)
	case "verack":
		fmt.Println("Processing verack message")
	case "inv":
		fmt.Println("Processing inv message")
		processInvMessage(payload, conn)
	case "ping":
		fmt.Println("Processing ping message")
		sendPongMessage(conn, payload)
	case "tx":
		fmt.Println("Processing tx message")
		displayTransactionInfo(payload)
	case "block":
		fmt.Println("Processing block message")
		displayBlockInfo(payload)
	case "sendcmpct":
		fmt.Println("Processing sendcmpct message")
	case "getheaders":
		fmt.Println("Processing getheaders message")
	case "feefilter":
		fmt.Println("Processing feefilter message")
	default:
		fmt.Printf("Received unknown message: %s\n", command)
	}
}

// sendVerackMessage sends a "verack" message over the provided network connection.
// It constructs the message and writes it to the connection.
// If there is an error while sending the message, it prints the error to the console.
func sendVerackMessage(conn net.Conn) {
	message := constructMessage("verack", []byte{})
	_, err := conn.Write(message)
	if err != nil {
		fmt.Println("Error sending verack message:", err)
	}
}

// sendPongMessage sends a pong message to the specified connection with the given payload.
// It constructs the message using the "pong" message type and the provided payload.
// If there is an error while sending the message, it prints the error to the console.
func sendPongMessage(conn net.Conn, payload []byte) {
	message := constructMessage("pong", payload)
	_, err := conn.Write(message)
	if err != nil {
		fmt.Println("Error sending pong message:", err)
	}
}

// processInvMessage processes the inventory message payload received from a network connection.
// It reads the count of inventory items from the payload and then reads each item's type and hash.
// Based on the type, it sends a "getdata" message to the network connection.
// The function takes the payload as a byte slice and the network connection as parameters.
func processInvMessage(payload []byte, conn net.Conn) {
	buf := bytes.NewReader(payload)
	var count uint8
	err := binary.Read(buf, binary.LittleEndian, &count)
	if err != nil {
		fmt.Println("Error reading inv message count:", err)
		return
	}

	for i := 0; i < int(count); i++ {
		var invType uint32
		var hash [32]byte
		err = binary.Read(buf, binary.LittleEndian, &invType)
		if err != nil {
			fmt.Println("Error reading inv type:", err)
			return
		}
		err = binary.Read(buf, binary.LittleEndian, &hash)
		if err != nil {
			fmt.Println("Error reading inv hash:", err)
			return
		}

		switch invType {
		case 1: // Type 1 indicates a transaction
			sendGetDataMessage(conn, invType, hash)
		case 2: // Type 2 indicates a block
			sendGetDataMessage(conn, invType, hash)
		}
	}
}

// sendGetDataMessage sends a "getdata" message to the specified connection with the given inventory type and hash.
// The function constructs the message, writes it to the connection, and handles any errors that occur.
func sendGetDataMessage(conn net.Conn, invType uint32, hash [32]byte) {
	var buf bytes.Buffer
	buf.WriteByte(1) // count
	binary.Write(&buf, binary.LittleEndian, invType)
	buf.Write(hash[:])
	message := constructMessage("getdata", buf.Bytes())
	_, err := conn.Write(message)
	if err != nil {
		fmt.Println("Error sending getdata message:", err)
	}
}

// Example of how to decode the compact format of 'bits'
func compactToTarget(bits uint32) *big.Int {
	exp := bits >> 24
	mant := bits & 0xffffff
	target := big.NewInt(int64(mant))
	target.Lsh(target, uint(8*(exp-3)))
	return target
}

// Helper function to reverse bytes
func reverseBytes(data []byte) []byte {
	for i, j := 0, len(data)-1; i < j; i, j = i+1, j-1 {
		data[i], data[j] = data[j], data[i]
	}
	return data
}

// parseTransactions parses the given block data and returns a slice of transactions.
// It takes a byte slice `blockData` as input and returns a slice of `Transaction`.
// The function reads the block data using a `bytes.Reader` and moves the buffer to the position where transactions start.
// It then reads the transaction count using `readVarInt` function and iterates over the count to read each transaction using `readTransaction` function.
// The transactions are appended to the `transactions` slice and returned at the end.
func parseTransactions(blockData []byte) []Transaction {
	var transactions []Transaction
	buf := bytes.NewReader(blockData)

	// Move the buffer to the position where transactions start
	buf.Seek(80, io.SeekStart)

	txCount := readVarInt(buf)

	for i := uint64(0); i < txCount; i++ {
		tx, _ := readTransaction(buf)
		transactions = append(transactions, tx)
	}

	return transactions
}

// readTransaction reads a transaction from the given buffer and returns a Transaction struct and an error, if any.
// The buffer should contain the serialized transaction data.
// The function parses the buffer and populates the Transaction struct with the transaction details.
// It returns the populated Transaction struct and nil error if successful, otherwise it returns an error.
func readTransaction(buf *bytes.Reader) (Transaction, error) {
	var tx Transaction
	start := buf.Size() - int64(buf.Len())
	tx.Version = binary.LittleEndian.Uint32(readBytes(buf, 4))

	inCount := readVarInt(buf)
	tx.Inputs = make([]TxInput, inCount)

	for i := uint64(0); i < inCount; i++ {
		var input TxInput
		input.PrevTx = readBytes(buf, 32)
		input.PrevIndex = binary.LittleEndian.Uint32(readBytes(buf, 4))
		scriptLength := readVarInt(buf)
		input.ScriptSig = readBytes(buf, int(scriptLength))
		input.Sequence = binary.LittleEndian.Uint32(readBytes(buf, 4))
		tx.Inputs[i] = input
	}

	outCount := readVarInt(buf)
	tx.Outputs = make([]TxOutput, outCount)

	for i := uint64(0); i < outCount; i++ {
		var output TxOutput
		output.Value = binary.LittleEndian.Uint64(readBytes(buf, 8))
		scriptLength := readVarInt(buf)
		output.ScriptPubKey = readBytes(buf, int(scriptLength))
		tx.Outputs[i] = output
	}

	tx.LockTime = binary.LittleEndian.Uint32(readBytes(buf, 4))
	tx.Hash = doubleSHA256(readBytesFromStart(buf, start, buf.Size()-int64(buf.Len())))

	return tx, nil
}

// readBytes reads the specified number of bytes from the given buffer and returns them as a byte slice.
func readBytes(buf *bytes.Reader, length int) []byte {
	bytes := make([]byte, length)
	buf.Read(bytes)
	return bytes
}

// readBytesFromStart reads a range of bytes from the given buffer starting from the specified start position (inclusive) and ending at the specified end position (exclusive).
// It returns the read bytes as a byte slice.
func readBytesFromStart(buf *bytes.Reader, start int64, end int64) []byte {
	currentPos := buf.Size() - int64(buf.Len())
	buf.Seek(start, io.SeekStart)
	bytes := make([]byte, end-start)
	buf.Read(bytes)
	buf.Seek(currentPos, io.SeekStart)
	return bytes
}

// displayBlockInfo displays information about a block.
// It takes a byte slice representing the block as input and prints various details about the block.
func displayBlockInfo(block []byte) {
	var buf = bytes.NewReader(block)
	var version int32
	var prevBlock [32]byte
	var merkleRoot [32]byte
	var timestamp uint32
	var bits uint32
	var nonce uint32

	binary.Read(buf, binary.LittleEndian, &version)
	binary.Read(buf, binary.LittleEndian, &prevBlock)
	binary.Read(buf, binary.LittleEndian, &merkleRoot)
	binary.Read(buf, binary.LittleEndian, &timestamp)
	binary.Read(buf, binary.LittleEndian, &bits)
	binary.Read(buf, binary.LittleEndian, &nonce)

	//Reconstruct the hash
	headerBuf := new(bytes.Buffer)
	binary.Write(headerBuf, binary.LittleEndian, version)
	headerBuf.Write(prevBlock[:])
	headerBuf.Write(merkleRoot[:])
	binary.Write(headerBuf, binary.LittleEndian, timestamp)
	binary.Write(headerBuf, binary.LittleEndian, bits)
	binary.Write(headerBuf, binary.LittleEndian, nonce)

	// Calculate the hash
	hash := doubleSHA256(headerBuf.Bytes())
	hashReversed := reverseBytes(hash[:])

	// Decode 'bits' into the target difficulty
	target := compactToTarget(bits)

	// Convert hash to a big integer for comparison
	hashInt := new(big.Int).SetBytes(hashReversed)

	// Compare the computed hash against the target
	isValid := hashInt.Cmp(target) <= 0

	fmt.Printf("Block Version: %d\n", version)
	fmt.Printf("Previous Block: %x\n", prevBlock)
	fmt.Printf("Merkle Root: %x\n", merkleRoot)
	fmt.Printf("Timestamp: %s\n", time.Unix(int64(timestamp), 0).Format(time.RFC1123))
	fmt.Printf("Difficulty Bits: %d\n", bits)
	fmt.Printf("Nonce: %d\n", nonce)
	fmt.Printf("Calculated Block Hash: %x\n", hashReversed)
	fmt.Printf("Hash is valid: %t\n", isValid)

	// Parse and display transactions
	transactions := parseTransactions(block)
	fmt.Printf("Displaying two transactions from %d for better view of logs", len(transactions))
	for i, tx := range transactions {
		if i >= 2 {
			break
		}
		fmt.Printf("Transaction %d: %x\n", i+1, tx.Hash)
		for j, input := range tx.Inputs {
			fmt.Printf("  Input %d: Previous Tx: %x, Index: %d, Sequence: %d\n", j+1, input.PrevTx, input.PrevIndex, input.Sequence)
		}
		for k, output := range tx.Outputs {
			fmt.Printf("  Output %d: Value: %d, Script: %x\n", k+1, output.Value, output.ScriptPubKey)
		}
	}

}

// displayTransactionInfo displays information about a transaction.
// It takes a byte slice representing the transaction as input and prints various details of the transaction.
// The transaction is expected to be in a specific format, as defined by the Bitcoin protocol.
// The function reads the transaction data from the byte slice and prints the version, input count, inputs, output count, outputs, and lock time of the transaction.
// Each input and output is printed with its respective details such as previous output, script length, script signature, value, and script public key.
func displayTransactionInfo(tx []byte) {
	var buf = bytes.NewReader(tx)
	var version int32
	var inCount, outCount uint64
	var lockTime uint32

	binary.Read(buf, binary.LittleEndian, &version)
	inCount = readVarInt(buf)

	fmt.Printf("Transaction Version: %d\n", version)
	fmt.Printf("Input Count: %d\n", inCount)

	for i := uint64(0); i < inCount; i++ {
		var prevOutput [32]byte
		var prevIndex uint32
		var scriptLength uint64
		var sequence uint32

		binary.Read(buf, binary.LittleEndian, &prevOutput)
		binary.Read(buf, binary.LittleEndian, &prevIndex)
		scriptLength = readVarInt(buf)
		scriptSig := make([]byte, scriptLength)
		buf.Read(scriptSig)
		binary.Read(buf, binary.LittleEndian, &sequence)

		fmt.Printf("Input %d:\n", i)
		fmt.Printf("  Previous Output: %x\n", prevOutput)
		fmt.Printf("  Previous Index: %d\n", prevIndex)
		fmt.Printf("  Script Length: %d\n", scriptLength)
		fmt.Printf("  Script Signature: %x\n", scriptSig)
		fmt.Printf("  Sequence: %d\n", sequence)
	}

	outCount = readVarInt(buf)
	fmt.Printf("Output Count: %d\n", outCount)

	for i := uint64(0); i < outCount; i++ {
		var value uint64
		var scriptLength uint64

		binary.Read(buf, binary.LittleEndian, &value)
		scriptLength = readVarInt(buf)
		scriptPubKey := make([]byte, scriptLength)
		buf.Read(scriptPubKey)

		fmt.Printf("Output %d:\n", i)
		fmt.Printf("  Value: %d\n", value)
		fmt.Printf("  Script Length: %d\n", scriptLength)
		fmt.Printf("  Script Public Key: %x\n", scriptPubKey)
	}

	binary.Read(buf, binary.LittleEndian, &lockTime)
	fmt.Printf("Lock Time: %d\n", lockTime)
}

// readVarInt reads a variable-length integer from the given bytes.Reader.
// It returns the decoded integer value.
func readVarInt(buf *bytes.Reader) uint64 {
	var result uint64
	var prefix byte
	binary.Read(buf, binary.LittleEndian, &prefix)

	switch prefix {
	case 0xFD:
		var value uint16
		binary.Read(buf, binary.LittleEndian, &value)
		result = uint64(value)
	case 0xFE:
		var value uint32
		binary.Read(buf, binary.LittleEndian, &value)
		result = uint64(value)
	case 0xFF:
		binary.Read(buf, binary.LittleEndian, &result)
	default:
		result = uint64(prefix)
	}

	return result
}

// constructMessage constructs a message by combining the magic bytes, command, payload length, checksum, and payload.
// It returns the constructed message as a byte slice.
// The constructed message has a length of 24 bytes plus the length of the payload.
// The magic bytes are copied to the first 4 bytes of the message.
// The command is copied to the next 12 bytes of the message.
// The payload length is written as a 4-byte little-endian integer at bytes 16 to 19 of the message.
// The checksum is computed using the doubleSHA256 function and copied to bytes 20 to 23 of the message.
// The payload is copied to the remaining bytes of the message.
func constructMessage(command string, payload []byte) []byte {
	message := make([]byte, 24+len(payload))

	// Copy magic bytes
	copy(message[0:4], []byte(magicBytes))

	// Copy command
	cmdBytes := make([]byte, 12)
	copy(cmdBytes, command)
	copy(message[4:16], cmdBytes)

	// Write payload length
	binary.LittleEndian.PutUint32(message[16:20], uint32(len(payload)))

	// Compute and copy checksum
	checksum := doubleSHA256(payload)
	copy(message[20:24], checksum[:4])

	// Copy payload
	copy(message[24:], payload)

	return message
}

// createVersionMessage creates a version message for a network protocol.
// It returns a byte slice containing the version message.
func createVersionMessage() []byte {
	var buf bytes.Buffer

	binary.Write(&buf, binary.LittleEndian, int32(70015))               // Protocol version
	binary.Write(&buf, binary.LittleEndian, uint64(1))                  // Services
	binary.Write(&buf, binary.LittleEndian, time.Now().Unix())          // Timestamp
	binary.Write(&buf, binary.LittleEndian, uint64(1))                  // Receiver services
	buf.Write(make([]byte, 16))                                         // Receiver IP address
	binary.Write(&buf, binary.BigEndian, uint16(8333))                  // Receiver port
	binary.Write(&buf, binary.LittleEndian, uint64(1))                  // Sender services
	buf.Write(make([]byte, 16))                                         // Sender IP address
	binary.Write(&buf, binary.BigEndian, uint16(8333))                  // Sender port
	binary.Write(&buf, binary.LittleEndian, uint64(0xdeadbeefcafebabe)) // Nonce
	buf.WriteByte(0)                                                    // User agent
	binary.Write(&buf, binary.LittleEndian, int32(0))                   // Start height
	buf.WriteByte(0)                                                    // Relay

	return buf.Bytes()
}

// sendVersionMessage sends a version message to the specified network connection.
// It creates a version payload, constructs a message with the payload, and writes it to the connection.
// If there is an error while sending the message, it prints the error to the console.
func sendVersionMessage(conn net.Conn) {
	payload := createVersionMessage()
	message := constructMessage("version", payload)
	_, err := conn.Write(message)
	if err != nil {
		fmt.Println("Error sending version message:", err)
	}
}

// main is the entry point of the program.
// It establishes a connection with a Bitcoin node,
// sends a version message, and handles incoming messages.
func main() {
	for {
		conn, err := net.Dial("tcp", nodeAddr)
		if err != nil {
			fmt.Println("Error connecting:", err)
			time.Sleep(5 * time.Second)
			continue
		}

		fmt.Println("Connected to Bitcoin node")
		defer conn.Close()

		sendVersionMessage(conn)
		handleIncomingMessages(conn)
	}
}
