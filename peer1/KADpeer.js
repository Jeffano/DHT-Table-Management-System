// Importing the 'yargs' module for parsing command-line arguments
const yargs = require("yargs");

// Importing the 'hideBin' helper function from the 'yargs/helpers' module
const { hideBin } = require("yargs/helpers");

// Importing the 'crypto' module for cryptographic functions
const crypto = require("crypto");

// Importing the 'net' module for creating TCP server and client sockets
const net = require("net");

// Initialize an empty array to represent the Distributed Hash Table (DHT)
let DHT_TABLE = [];

// Initialize an empty array to represent the initial packet
let initalPacket = [];

// Generate a random number to simulate the clock for timestamp
let clock = Math.floor(Math.random() * 999) + 1;

// Generate a random port number for the server
let serverPort = Math.floor(Math.random() * 9999) + 1000;

// Parse command-line arguments using yargs
const argv = yargs(hideBin(process.argv))
    // Define option for specifying peer name
    .option("n", {
        describe: "Peer Name", // Description of the option
        type: "string", // Type of the option value
        demandOption: true, // Whether the option is required
    })
    // Define option for specifying peer IP and port
    .option("p", {
        describe: "Peer IP and port", // Description of the option
        type: "string", // Type of the option value
        demandOption: false, // Whether the option is required
    }).argv;

// If there is no peer IP specified via command line arguments
if (!argv.p) {
    // Create a TCP server instance
    const server = net.createServer();

    // Start the stopWatch to keep track of time
    stopWatch();

    // Initialize the Distributed Hash Table (DHT) table
    initDHTTable();

    // Define host, port, and name for the peer
    const host = "127.0.0.1";
    const port = 6789;
    const name = "peer1";
    const nameData = stringToBytes(name);
    const address = host.split(".");

    // Start the server listening on the specified port and host
    server.listen(port, host);

    // Get the ID of the current peer based on host and port
    const peerID = getClientID(host, port);

    // Log the address and ID of the current peer
    console.log(
        `This peer address is ${host}:${port} located at server [${peerID}]`
    );

    // Event handler for when a client connects to the server
    server.on("connection", (socket) => {
        // Initialize an empty packet buffer
        let packet = Buffer.alloc(12 + name.length + countPeers(DHT_TABLE) * 11).fill(0);

        // Store header information in the packet buffer
        setBitInPacket(packet, 9, 0, 4); // ITP version
        setBitInPacket(packet, 1, 4, 7); // Message type
        setBitInPacket(packet, countPeers(DHT_TABLE), 11, 9); // Number of peers in DHT
        setBitInPacket(packet, name.length, 20, 12); // Length of peer name
        setBitInPacket(packet, parseInt(address[0]), 32, 8); // IP address octet 1
        setBitInPacket(packet, parseInt(address[1]), 40, 8); // IP address octet 2
        setBitInPacket(packet, parseInt(address[2]), 48, 8); // IP address octet 3
        setBitInPacket(packet, parseInt(address[3]), 56, 8); // IP address octet 4
        setBitInPacket(packet, port, 64, 16); // Server port

        // Store peer name bytes in the packet buffer
        nameData.forEach((byte, i) => {
            packet[12 + i] = byte;
        });

        // Store peer information for each peer in the DHT in the packet buffer
        if (countPeers(DHT_TABLE) > 0) {
            let offset = 12 + name.length;
            for (let i = 0; i < 32; i++) {
                if (DHT_TABLE[i] != null) {
                    DHT_TABLE[i].forEach((peer) => {
                        setBitInPacket(
                            packet,
                            parseInt(peer.ip.split(".")[0]),
                            offset * 8,
                            8
                        );
                        setBitInPacket(
                            packet,
                            parseInt(peer.ip.split(".")[1]),
                            offset * 8 + 8,
                            8
                        );
                        setBitInPacket(
                            packet,
                            parseInt(peer.ip.split(".")[2]),
                            offset * 8 + 16,
                            8
                        );
                        setBitInPacket(
                            packet,
                            parseInt(peer.ip.split(".")[3]),
                            offset * 8 + 24,
                            8
                        );
                        setBitInPacket(packet, peer.port, offset * 8 + 32, 16);
                        offset += 6;
                    });
                }
            }
        }

        // Write the packet buffer to the connected client
        socket.write(packet);

        // Event handler for when data is received from the client
        socket.on("data", (data) => {
            // Get client ID based on host and port
            const peerID = getClientID(host, port);

            // Parse the received data packet
            let version = decodeBitSequence(data, 0, 4);
            let messageType = decodeBitSequence(data, 4, 7);
            let peerCount = decodeBitSequence(data, 11, 9);
            let nameLength = decodeBitSequence(data, 20, 12);
            let address1 = decodeBitSequence(data, 32, 8);
            let address2 = decodeBitSequence(data, 40, 8);
            let address3 = decodeBitSequence(data, 48, 8);
            let address4 = decodeBitSequence(data, 56, 8);
            let address = `${address1}.${address2}.${address3}.${address4}`;
            let peerPort = decodeBitSequence(data, 64, 16);
            let peerName = bytesToString(data.slice(12, 12 + nameLength));
            let offset = 12 + nameLength;

            // Log connection information
            console.log(`\nConnected from peer ${address}:${peerPort}\n`);

            // Check if the message type is not a Hello message and return if true
            if (messageType != 2) {
                return;
            }

            // Get server ID based on peer IP and port
            let Server_ID = getClientID(address, peerPort);

            // Push peer information to the DHT table
            updateDHTBucket(
                DHT_TABLE,
                { ip: address, port: peerPort, id: Server_ID },
                peerID
            );

            // Get current bucket information
            let myBucket = getNonEmptyBucketInfo(DHT_TABLE);
            console.log(`My DHT:`);
            myBucket.forEach((bucket) => {
                console.log(`[${bucket}]\n`);
            });

            // Log the received Hello message
            console.log(
                `Received Hello Message from ${peerName} ${Server_ID} along with DHT`
            );

            // Parse and process peer information received in the Hello message
            if (peerCount > 0) {
                for (let i = 0; i < peerCount; i++) {
                    let peerAddress1 = decodeBitSequence(data, offset * 8, 8);
                    let peerAddress2 = decodeBitSequence(data, offset * 8 + 8, 8);
                    let peerAddress3 = decodeBitSequence(data, offset * 8 + 16, 8);
                    let peerAddress4 = decodeBitSequence(data, offset * 8 + 24, 8);
                    let peerAddress = `${peerAddress1}.${peerAddress2}.${peerAddress3}.${peerAddress4}`;
                    let dhtPort = decodeBitSequence(data, offset * 8 + 32, 16);
                    offset += 6;
                    let id = getClientID(peerAddress, dhtPort);
                    console.log(`[${peerAddress}:${dhtPort}, ${id}]\n`);
                    updateDHTBucket(
                        DHT_TABLE,
                        // IP address and port of the peer
                        { ip: address, port: peerPort, id: Server_ID },
                        peerID
                    );
                }
            }
            // Get updated bucket information after peer addition
            myBucket = getNonEmptyBucketInfo(DHT_TABLE);
            console.log(`Refresh k-Bucket operation is performed\n`);
            console.log(`My DHT:`);
            myBucket.forEach((bucket) => {
                console.log(`[${bucket}]`);
            });
        });
        // Event handler for when the socket is closed
        socket.on("close", () => { });

        // Event handler for socket errors
        socket.on("error", (err) => {
            if (err.code == "ECONNREFUSED")
                console.log(
                    `Client is no longer listening on ${err.address}:${err.port}`
                );
            else console.log(`handled error:\n${err}`);
            console.log(`error has been detected please restart all peer nodes`);
        });
    });
} else {

    // Extracting peer IP and port from command line arguments
    const [peerIp, peerPort] = argv.p.split(":");
    // Creating a new socket for the client
    const clientSocket = new net.Socket();
    // Variable to store the client port
    let clientPort;

    // Connecting the client socket to the specified peer IP and port
    clientSocket.connect(parseInt(peerPort, 10), peerIp);

    // Event handler for when data is received from the peer
    clientSocket.on("data", (data) => {
        // Getting the client ID based on the peer IP and the local port of the client socket
        const peerID = getClientID(peerIp, clientSocket.localPort);
        // Storing the local port of the client socket
        clientPort = clientSocket.localPort;

        // Parsing the received data packet
        let version = decodeBitSequence(data, 0, 4);
        // Checking if the received ITP version is valid
        if (version != 9) {
            console.log("Invalid ITP version");
            return;
        }
        let messageType = decodeBitSequence(data, 4, 7);
        let peerCount = decodeBitSequence(data, 11, 9);
        let nameLength = decodeBitSequence(data, 20, 12);
        let address1 = decodeBitSequence(data, 32, 8);
        let address2 = decodeBitSequence(data, 40, 8);
        let address3 = decodeBitSequence(data, 48, 8);
        let address4 = decodeBitSequence(data, 56, 8);
        let address = `${address1}.${address2}.${address3}.${address4}`;
        let peerPort = decodeBitSequence(data, 64, 16);
        let peerName = bytesToString(data.slice(12, 12 + nameLength));
        let offset = 12 + nameLength;
        // Logging connection information
        console.log(`Connected to ${peerName}:${peerPort} at Stopwatchstamp: ${clock}`);
        console.log(
            `\nThis peer is ${address}:${clientSocket.localPort} located at ${argv.n} [${peerID}]`
        );
        // Handling different message types
        if (messageType != 1) {
            return;
        }
        let Server_ID = getClientID(address, peerPort);
        console.log(
            `\nReceived Welcome Message from server ${Server_ID} along with DHT`
        );
        // Parsing and processing peer entries in the received DHT
        if (peerCount > 0) {
            for (let i = 0; i < peerCount; i++) {
                let peerAddress1 = decodeBitSequence(data, offset * 8, 8);
                let peerAddress2 = decodeBitSequence(data, offset * 8 + 8, 8);
                let peerAddress3 = decodeBitSequence(data, offset * 8 + 16, 8);
                let peerAddress4 = decodeBitSequence(data, offset * 8 + 24, 8);
                let peerAddress = `${peerAddress1}.${peerAddress2}.${peerAddress3}.${peerAddress4}`;
                let peerPort = decodeBitSequence(data, offset * 8 + 32, 16);
                offset += 6;
                let id = getClientID(peerAddress, peerPort);
                console.log(`[${peerAddress}:${peerPort}, ${id}]\n`);
                updateDHTBucket(
                    DHT_TABLE,
                    { ip: peerAddress, port: peerPort, id: id },
                    peerID
                );
            }
        } else {
            console.log(`[]\n`);
        }
        // Adding the server entry to the DHT
        updateDHTBucket(
            DHT_TABLE,
            {
                ip: peerIp,
                port: peerPort,
                id: Server_ID,
            },
            peerID
        );
        // Refreshing the k-Bucket operation
        let myBucket = getNonEmptyBucketInfo(DHT_TABLE);
        console.log(`Refresh k-Bucket operation is performed\n`);
        console.log(`My DHT:`);
        myBucket.forEach((bucket) => {
            console.log(`[${bucket}]`);
        });
        // Creating an initial packet based on the updated DHT
        let table = noNullDHT();
        initalPacket = createinitalPacket(table, {
            senderName: argv.n,
            address: address,
            port: clientSocket.localPort,
        });
        // Sending hello packets to peers in the DHT
        sendHello(noNullDHT())
            .then(() => {
                console.log(`Hello packet has been sent.`);
            })
            .catch((error) => {
                console.log("An error occurred while sending hello packets:", error);
            });
        // Destroying the client socket
        clientSocket.destroy();
    });

    // Event handler for when the client socket is closed
    clientSocket.on("close", () => { });
    // Event handler for socket errors
    clientSocket.on("error", (err) => {
        console.log("Connection error: ", err);
    });

    // Setting a timeout for creating a server to listen for incoming connections
    setTimeout(() => {
        const peerServer = net.createServer();
        peerServer.listen(clientPort, peerIp);
        // Event handler for incoming connections to the peer server
        peerServer.on("connection", (sock) => {
            // Event handler for data received from connected peers
            sock.on("data", (data) => {
                const peerID = getClientID(sock.localAddress, sock.localPort);
                let version = decodeBitSequence(data, 0, 4);
                let messageType = decodeBitSequence(data, 4, 7);
                let peerCount = decodeBitSequence(data, 11, 9);
                let nameLength = decodeBitSequence(data, 20, 12);
                let address1 = decodeBitSequence(data, 32, 8);
                let address2 = decodeBitSequence(data, 40, 8);
                let address3 = decodeBitSequence(data, 48, 8);
                let address4 = decodeBitSequence(data, 56, 8);
                let address = `${address1}.${address2}.${address3}.${address4}`;
                let peerPort = decodeBitSequence(data, 64, 16);
                let peerName = bytesToString(data.slice(12, 12 + nameLength));
                let offset = 12 + nameLength;
                // Checking if the received message type is a hello message
                if (messageType != 2) {
                    return;
                }
                let Server_ID = getClientID(address, peerPort);
                // Adding the peer information to the DHT
                updateDHTBucket(
                    DHT_TABLE,
                    { ip: address, port: peerPort, id: Server_ID },
                    peerID
                );
                console.log(
                    `Received Hello Message from ${peerName} ${Server_ID} along with DHT`
                );
                // Parsing and processing peer entries in the received DHT
                if (peerCount > 0) {
                    for (let i = 0; i < peerCount; i++) {
                        let peerAddress1 = decodeBitSequence(data, offset * 8, 8);
                        let peerAddress2 = decodeBitSequence(data, offset * 8 + 8, 8);
                        let peerAddress3 = decodeBitSequence(data, offset * 8 + 16, 8);
                        let peerAddress4 = decodeBitSequence(data, offset * 8 + 24, 8);
                        let peerAddress = `${peerAddress1}.${peerAddress2}.${peerAddress3}.${peerAddress4}`;
                        let dhtPort = decodeBitSequence(data, offset * 8 + 32, 16);
                        offset += 6;
                        let id = getClientID(peerAddress, dhtPort);
                        console.log(`[${peerAddress}:${dhtPort}, ${id}]\n`);
                        updateDHTBucket(
                            DHT_TABLE,
                            { ip: address, port: peerPort, id: Server_ID },
                            peerID
                        );
                    }
                }
                // Refreshing the k-Bucket operation
                myBucket = getNonEmptyBucketInfo(DHT_TABLE);
                console.log(`Refresh k-Bucket operation is performed\n`);
                console.log(`My DHT:`);
                myBucket.forEach((bucket) => {
                    console.log(`[${bucket}]`);
                });
            });
        });
    }, 500);
}

/**
 * Converts an array of bytes to a string.
 * @param {number[]} array - The array of bytes to convert to a string.
 * @returns {string} - The resulting string.
 */
function bytesToString(array) {
    // Initialize an empty string to store the resulting string
    var result = "";
    // Iterate through each byte in the array
    for (var i = 0; i < array.length; ++i) {
        // Convert each byte to its corresponding character and concatenate to the result
        result += String.fromCharCode(array[i]);
    }
    // Return the resulting string
    return result;
}

/**
 * Connects to the specified peer and sends a "hello" message.
 * @param {Object} peer - An object representing the peer with properties 'ip' and 'port'.
 * @returns {Promise} - A promise that resolves when the "hello" message is successfully sent, or rejects if an error occurs.
 */
async function connectAndSend(peer) {
    // Create a new promise to handle the connection and message sending process
    return new Promise((resolve, reject) => {
        // Create a new socket client
        const client = new net.Socket();

        // Event listener for errors that occur during the connection attempt
        client.on("error", (err) => {
            // Log the error message indicating the connection failure
            console.log(`Error connecting to ${peer.ip}:${peer.port}: ${err.message}`);
            // Destroy the client socket
            client.destroy();
            // Reject the promise with the error
            reject(err);
        });

        // Event listener for when the client successfully connects to the peer
        client.on("connect", () => {
            // Write the initial packet to the client socket
            client.write(initalPacket);
            // End the connection
            client.end();
            // Resolve the promise to indicate successful message sending
            resolve();
        });

        // Initiate the connection to the peer by specifying the peer's port and IP address
        client.connect(peer.port, peer.ip);
    }).catch((error) => {
        // If an error occurs during the connection or message sending process, catch it here
        console.log(`Failed to send hello to ${peer.ip}:${peer.port}, error: ${error.message}`);
    });
}

/**
 * Counts the total number of peers stored in the DHT table.
 * @param {Array} DHT_TABLE - The distributed hash table.
 * @returns {number} - The total count of peers.
 */
function countPeers(DHT_TABLE) {
    // Reduce function to accumulate the total count of peers across all buckets
    return DHT_TABLE.reduce(
        (acc, bucket) => acc + (bucket ? bucket.length : 0),
        0
    );
}

/**
 * Creates an initial packet for communication with other peers, including sender information and DHT table data.
 * @param {Array} DHT_TABLE - The distributed hash table containing information about other peers.
 * @param {Object} mypeer_information - Information about the sender peer.
 * @param {string} mypeer_information.senderName - The name of the sender peer.
 * @param {string} mypeer_information.address - The IP address of the sender peer.
 * @param {number} mypeer_information.port - The port of the sender peer.
 * @returns {Buffer} The initial packet to be sent to other peers.
 */
function createinitalPacket(DHT_TABLE, mypeer_information) {
    // Calculate the number of peers in the DHT table
    const numberOfPeers = countPeers(DHT_TABLE);

    // Calculate the size of the packet
    const packetSize =
        12 + mypeer_information.senderName.length + numberOfPeers * (1 + 4 + 2);

    // Initialize the packet buffer
    const packet = Buffer.alloc(packetSize).fill(0);

    // Store information about the packet
    setBitInPacket(packet, 9, 0, 4); // ITP version
    setBitInPacket(packet, 2, 4, 7); // Message type (2 for initial packet)
    setBitInPacket(packet, numberOfPeers, 11, 9); // Number of peers in DHT table
    setBitInPacket(packet, mypeer_information.senderName.length, 20, 12); // Length of sender name

    // Store sender IP address in the packet
    mypeer_information.address.split(".").forEach((part, index) => {
        setBitInPacket(packet, parseInt(part), 32 + index * 8, 8);
    });

    // Store sender port in the packet
    setBitInPacket(packet, mypeer_information.port, 64, 16);

    // Store sender name in the packet
    let offset = 12;
    const nameData = stringToBytes(mypeer_information.senderName);
    nameData.forEach((byte, i) => (packet[12 + i] = byte));
    offset += mypeer_information.senderName.length;

    // Store DHT table data in the packet
    if (numberOfPeers > 0) {
        DHT_TABLE
            .filter((bucket) => bucket != null) // Filter out empty buckets
            .forEach((bucket) => {
                bucket.forEach((peer) => {
                    // Store peer IP address in the packet
                    peer.ip.split(".").forEach((part, index) => {
                        setBitInPacket(packet, parseInt(part), offset * 8 + index * 8, 8);
                    });
                    // Store peer port in the packet
                    setBitInPacket(packet, peer.port, offset * 8 + 32, 16);
                    offset += 6; // Increment offset for the next peer
                });
            });
    }
    return packet;
}

/**
 * Parses a binary value from a packet at a specified offset with a specified length.
 * @param {number[]} packet - The packet (array of bytes) containing the binary value.
 * @param {number} offset - The bit offset in the packet where the binary value starts.
 * @param {number} length - The length of the binary value in bits.
 * @returns {number} - The parsed binary value.
 */
function decodeBitSequence(packet, offset, length) {
    // Initialize an empty string to store the binary representation of the parsed value
    let number = "";
    // Iterate through each bit of the binary value
    for (var i = 0; i < length; i++) {
        // Calculate the byte position in the packet where the current bit is located
        let bytePosition = Math.floor((offset + i) / 8);
        // Calculate the bit position within the byte where the current bit is located
        let bitPosition = 7 - ((offset + i) % 8);
        // Extract the bit value at the specified position from the packet
        let bit = (packet[bytePosition] >> bitPosition) % 2;
        // Append the extracted bit to the binary representation
        number = (number << 1) | bit;
    }
    // Return the parsed binary value
    return number;
}

/**
 * Generates a unique client ID based on the provided IP address and port.
 * @param {string} ip - IP address of the client.
 * @param {number} port - Port number of the client.
 * @returns {string} The generated client ID.
 */
function getClientID(ip, port) {
    // Create a cryptographic hash function with SHAKE256 algorithm and output length of 4 bytes
    const hashset = crypto.createHash("shake256", { outputLength: 4 });

    // Update the hash function with the concatenation of IP address and port
    hashset.update(`${ip}:${port}`);

    // Calculate the hash digest in hexadecimal format
    const haxes = hashset.digest("hex");

    // Return the client ID
    return haxes;
}

/**
 * Retrieves information about the current state of each bucket in the DHT table.
 * @param {Array} DHT_TABLE - The distributed hash table.
 * @returns {Array} - Information about peers stored in each bucket.
 */
function getNonEmptyBucketInfo(DHT_TABLE) {
    // Initialize an array to store bucket information
    let bucketInfoList = [];

    // Iterate through each bucket in the DHT table
    DHT_TABLE.forEach((bucket, index) => {
        // Check if the bucket is not empty and contains peers
        if (bucket && bucket.length > 0) {
            // Iterate through each peer in the bucket
            bucket.forEach((peer) => {
                // Construct a string with information about the peer and bucket
                let bucketInfo = `P${index}, ${peer.ip}:${peer.port}, ${peer.id}`;
                // Add the bucket information to the list
                bucketInfoList.push(bucketInfo);
            });
        }
    });

    // If no peers are found in the DHT, return a message indicating so
    if (bucketInfoList.length === 0) {
        return ["No peers found in DHT."];
    }

    // Return the list of bucket information
    return bucketInfoList;
}

/**
 * Converts a hexadecimal string to binary representation.
 * @param {string} hex - The hexadecimal string to convert.
 * @returns {string} The binary representation of the hexadecimal string.
 */
function hexToBinary(hex) {
    return hex
        .split("")
        .map((str) => parseInt(str, 16).toString(2).padStart(4, "0"))
        .join("");
}

/**
 * Initializes the DHT_TABLE by filtering out null entries and creating a new table.
 * @returns {Array} The initialized DHT table.
 */
function initDHTTable() {
    // Initialize an empty array to store the filtered DHT entries
    let table = [];

    // Initialize the base index for the new table
    let base = 0;

    // Iterate over the DHT_TABLE entries
    for (let i = 0; i < 32; i++) {
        // Check if the current entry is not null
        if (DHT_TABLE[i] != null) {
            // If not null, add the entry to the new table at the current base index
            table[base] = DHT_TABLE[i];

            // Increment the base index
            base++;
        }
    }

    // Return the filtered DHT table
    return table;
}

/**
 * Retrieves DHT entries without null values.
 * @returns {Array} - An array containing non-null DHT entries.
 */
function noNullDHT() {
    // Initialize an empty array to store non-null DHT entries
    let T = [];
    // Initialize a counter for indexing non-null DHT entries
    let e = 0;

    // Iterate through each entry in the DHT table
    for (let t = 0; t < DHT_TABLE.length; t++) {
        // Check if the current entry is not null
        if (DHT_TABLE[t] != null) {
            // If the entry is not null, add it to the array of non-null DHT entries
            T[e] = DHT_TABLE[t];
            // Increment the counter for indexing non-null entries
            e++;
        }
    }

    // Return the array containing non-null DHT entries
    return T;
}

/**
 * Calculates the length of the common prefix between two IDs.
 * @param {string} id1 - The first ID.
 * @param {string} id2 - The second ID.
 * @returns {number} The length of the common prefix between the two IDs.
 */
function prefixLength(id1, id2) {
    // Initialize the length of the common prefix
    let length = 0;

    // Convert the IDs to strings
    let Client_ID = id1.toString();
    let Server_ID = id2.toString();

    // Iterate through the characters of both IDs
    for (let i = 0; i < Client_ID.length && i < Server_ID.length; i++) {
        // If the characters at the current position are equal, increment the length
        if (Client_ID[i] === Server_ID[i]) {
            ++length;
        } else {
            // If characters are different, break the loop
            break;
        }
    }

    // Return the length of the common prefix
    return length;
}

/**
 * Refreshes the buckets in the DHT table with new peer information and logs the updated DHT table.
 * @param {Array} DHT_TABLE - The distributed hash table.
 * @param {Array} peersList - The list of peers to be added to the DHT table.
 * @param {string} Server_ID - The ID of the current server.
 */
function refreshBuckets(DHT_TABLE, peersList, Server_ID) {
    // Add peers to the DHT table
    updateDHTBucket(DHT_TABLE, peersList, Server_ID);

    // Log the current DHT table
    console.log("Current DHT Table:");
    DHT_TABLE.forEach((bucket, index) => {
        if (bucket && bucket.length > 0) {
            console.log(`Bucket ${index}:`);
            bucket.forEach((peer) => {
                console.log(
                    `- Peer ID: ${peer.id}, IP: ${peer.ip}, Port: ${peer.port}`
                );
            });
        }
    });
}

/**
 * Stores a binary value in a packet at a specified offset with a specified length.
 * @param {number[]} packet - The packet (array of bytes) to store the value in.
 * @param {number} value - The binary value to store.
 * @param {number} offset - The bit offset in the packet where the value will be stored.
 * @param {number} length - The length of the value in bits.
 */
function setBitInPacket(packet, value, offset, length) {
    // Calculate the position of the last bit to be stored
    let lastBitPosition = offset + length - 1;
    // Convert the value to a binary string
    let number = value.toString(2);
    // Initialize the index for traversing the binary string from the end
    let j = number.length - 1;
    // Iterate through each bit of the binary value
    for (var i = 0; i < number.length; i++) {
        // Calculate the byte position in the packet where the current bit will be stored
        let bytePosition = Math.floor(lastBitPosition / 8);
        // Calculate the bit position within the byte where the current bit will be stored
        let bitPosition = 7 - (lastBitPosition % 8);
        // Check if the current bit in the binary string is '0' or '1'
        if (number.charAt(j--) == "0") {
            // Clear the bit at the specified position in the packet by ANDing with its complement
            packet[bytePosition] &= ~(1 << bitPosition);
        } else {
            // Set the bit at the specified position in the packet by ORing with a 1 shifted to that position
            packet[bytePosition] |= 1 << bitPosition;
        }
        // Move to the next lower bit position in the packet
        lastBitPosition--;
    }
}

/**
 * Converts a string to an array of bytes.
 * @param {string} str - The input string to convert.
 * @returns {number[]} - An array of bytes representing the input string.
 */
function stringToBytes(str) {
    var ch,
        st,
        re = [];
    // Iterate through each character in the string
    for (var i = 0; i < str.length; i++) {
        // Get the Unicode code point of the character
        ch = str.charCodeAt(i);
        st = [];
        // Convert the Unicode code point to a sequence of bytes
        do {
            // Extract the lowest 8 bits of the code point and push it to the array
            st.push(ch & 0xff);
            // Right shift the code point by 8 bits to process the next byte
            ch = ch >> 8;
        } while (ch); // Continue until all bytes of the code point are processed
        // Concatenate the byte array for the current character to the result array
        re = re.concat(st.reverse());
    }
    // Return the resulting array of bytes
    return re;
}

/**
 * Sends a "hello" message to each peer in the provided DHT entries.
 * @param {Array} T - An array of DHT entries, each containing peers.
 * @returns {Promise} - A promise that resolves when all "hello" messages are sent.
 */
async function sendHello(T) {
    // Iterate through each DHT entry
    for (const entry of T) {
        // Iterate through each peer in the current DHT entry
        for (const peer of entry) {
            // Send a "hello" message to the current peer and wait for the operation to complete
            await connectAndSend(peer);
        }
    }
}

/**
 * Starts a stopWatch to update the global clock variable periodically.
 * The clock variable represents the timestamp.
 */
function stopWatch() {
    // Set interval to update the clock every 10 milliseconds
    setInterval(() => {
        // Increment the clock by 1 and wrap around if it exceeds the maximum value
        clock = (clock + 1) % 2 ** 32;
    }, 10);
}

/**
 * Pushes peer information into the appropriate bucket of the DHT table.
 * @param {Array} DHT_TABLE - The distributed hash table.
 * @param {Object} peer_information - Information about the peer to be added.
 * @param {string} peer_information.ip - The IP address of the peer.
 * @param {number} peer_information.port - The port number of the peer.
 * @param {string} peer_information.id - The ID of the peer.
 * @param {string} Server_ID - The ID of the current server.
 */
function updateDHTBucket(DHT_TABLE, peer_information, Server_ID) {
    // Extract peer information
    const { ip, port, id } = peer_information;

    // Calculate the shared prefix length between peer ID and server ID
    const sharedPrefixLength = prefixLength(
        hexToBinary(id),
        hexToBinary(Server_ID)
    );

    // Determine the index of the bucket based on the shared prefix length
    const bucket_Index_Val = sharedPrefixLength;

    // If the bucket is empty, add the peer information
    if (!DHT_TABLE[bucket_Index_Val]) {
        DHT_TABLE[bucket_Index_Val] = [];
    }

    // If the bucket is empty or not full, add the peer information
    if (DHT_TABLE[bucket_Index_Val].length === 0 && bucket_Index_Val < 32) {
        DHT_TABLE[bucket_Index_Val].push(peer_information);
        console.log(`Bucket P${bucket_Index_Val} has no value, adding ${id}\n`);
    } else {
        // If the bucket is full, compare distances to determine if an update is needed
        console.log(
            `Bucket P${bucket_Index_Val} is full, checking if we need to change the stored value`
        );

        // Get information about the existing peer in the bucket
        const currentPeer = DHT_TABLE[bucket_Index_Val][0];

        // Calculate distances between the existing peer and the server, and the new peer and the server
        const existingPeerDistance = xors(
            hexToBinary(currentPeer.id),
            hexToBinary(Server_ID)
        );
        const newPeerDistance = xors(hexToBinary(id), hexToBinary(Server_ID));

        // Determine if the new peer is closer than the existing peer to the server
        if (newPeerDistance < existingPeerDistance) {
            console.log(
                `${id} is closer than our current stored value ${currentPeer.id}, updating.`
            );
            // Update the stored value with the new peer information
            DHT_TABLE[bucket_Index_Val][0] = peer_information;
        } else {
            console.log(`Current value is closest, no update needed\n`);
        }
    }
}

/**
 * Performs bitwise XOR operation between two binary strings.
 * @param {string} a - The first binary string.
 * @param {string} b - The second binary string.
 * @returns {string} The result of the XOR operation.
 */
function xors(a, b) {
    // Initialize the result string
    let ans = "";

    // Iterate through the characters of the input strings
    for (let i = 0; i < a.length; i++) {
        // If the corresponding bits are equal, append '0' to the result, otherwise '1'
        ans += a[i] == b[i] ? "0" : "1";
    }

    // Return the result of the XOR operation
    return ans;
}
