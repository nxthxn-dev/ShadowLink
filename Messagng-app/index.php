<?php
session_start();
$server_url = "http://localhost:8000";

// Ensure the keys directory exists
$keys_dir = __DIR__ . "/keys";
if (!is_dir($keys_dir)) {
    mkdir($keys_dir, 0777, true);
}

// Function to communicate with FastAPI
function apiRequest($endpoint, $data, $method = "POST") {
    global $server_url;

    $json_data = json_encode($data, JSON_THROW_ON_ERROR); // Ensure proper JSON encoding

    // Debugging: Log the request payload
    file_put_contents("debug.log", "Sending to $endpoint: " . $json_data . "\n", FILE_APPEND);

    $options = [
        "http" => [
            "header"  => "Content-Type: application/json",
            "method"  => $method,
            "content" => $json_data,
            "ignore_errors" => true
        ]
    ];
    $context = stream_context_create($options);
    $response = file_get_contents("$server_url$endpoint", false, $context);

    // Ensure valid JSON response
    $decoded_response = json_decode($response, true);
    if ($decoded_response === null) {
        return ["status" => "❌ API Error", "error" => "Invalid JSON response from server"];
    }

    return $decoded_response;
}

// Handle user registration
if ($_SERVER["REQUEST_METHOD"] === "POST" && isset($_POST["register"])) {
    $username = trim($_POST["username"]);
    $_SESSION["username"] = $username;
    
    // Register the user on FastAPI
    $response = apiRequest("/register/", ["username" => $username]);

    echo json_encode($response);
    exit();
}

// Handle message sending
if ($_SERVER["REQUEST_METHOD"] === "POST" && isset($_POST["send"])) {
    if (!isset($_SESSION["username"])) {
        echo json_encode(["status" => "❌ Error: Username not set."]);
        exit();
    }

    $sender = $_SESSION["username"];
    $receiver = trim($_POST["receiver"]);
    $message = trim($_POST["message"]);

    if (empty($receiver) || empty($message)) {
        echo json_encode(["status" => "❌ Error: Fields cannot be empty."]);
        exit();
    }

    // Get receiver's public key
    $key_response = apiRequest("/get_public_key/", ["username" => $receiver]);

    if (!$key_response || !isset($key_response["public_key"])) {
        echo json_encode(["status" => "❌ Error: Receiver's public key not found."]);
        exit();
    }

    $public_key_pem = $key_response["public_key"];
    $publicKey = openssl_pkey_get_public($public_key_pem);

    if (!$publicKey) {
        echo json_encode(["status" => "❌ Error: Invalid receiver public key."]);
        exit();
    }

    // Encrypt message in chunks
    $max_length = 245;
    $encrypted_chunks = [];
    $message_bytes = str_split($message, $max_length);

    foreach ($message_bytes as $chunk) {
        openssl_public_encrypt($chunk, $encrypted_chunk, $publicKey);
        $encrypted_chunks[] = bin2hex($encrypted_chunk);
    }

    // Convert array to a single string
    $encrypted_message_hex = implode("|", $encrypted_chunks);

    // Load sender's private key for signing
    $privateKeyPath = "$keys_dir/{$sender}_private.pem";
    if (!file_exists($privateKeyPath)) {
        echo json_encode(["status" => "❌ Error: Private key for $sender not found."]);
        exit();
    }

    $privateKey = openssl_pkey_get_private(file_get_contents($privateKeyPath));
    if (!$privateKey) {
        echo json_encode(["status" => "❌ Error: Could not load private key."]);
        exit();
    }

    // Sign the message
    openssl_sign($message, $signature, $privateKey, OPENSSL_ALGO_SHA512);
    $signature_hex = bin2hex($signature);

    // Send encrypted message
    $response = apiRequest("/send/", [
        "sender" => $sender,
        "receiver" => $receiver,
        "encrypted_content" => $encrypted_message_hex,
        "signature" => $signature_hex
    ]);

    echo json_encode($response);
    exit();
}
?>

<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>Secure Chat</title>
    <script>
        let ws = new WebSocket("ws://localhost:8000/ws");

        ws.onmessage = function(event) {
            try {
                let data = JSON.parse(event.data);
                let messagesList = document.getElementById("messages");
                let li = document.createElement("li");

                let messageText = `<strong>${data.sender}:</strong> ${data.content}`;
                if (data.status) {
                    messageText += ` <span style="color:${data.status === '✅ Verified' ? 'green' : 'red'};">${data.status}</span>`;
                }

                li.innerHTML = messageText;
                messagesList.appendChild(li);
            } catch (error) {
                console.error("❌ Error parsing WebSocket message:", error);
            }
        };

        function registerUser(event) {
            event.preventDefault();
            let username = document.getElementById("username").value;

            fetch("", {
                method: "POST",
                headers: { "Content-Type": "application/x-www-form-urlencoded" },
                body: `register=1&username=${encodeURIComponent(username)}`
            })
            .then(response => response.json())
            .then(data => {
                alert(data.status);
                if (data.status === "✅ Registration successful") {
                    location.reload();
                }
            })
            .catch(error => alert("❌ Error: " + error));
        }

        function sendMessage(event) {
            event.preventDefault();
            let receiver = document.getElementById("receiver").value;
            let message = document.getElementById("message").value;

            if (message.trim() === "" || receiver.trim() === "") {
                alert("❌ Error: Fields cannot be empty.");
                return;
            }

            fetch("", {
                method: "POST",
                headers: { "Content-Type": "application/x-www-form-urlencoded" },
                body: `send=1&receiver=${encodeURIComponent(receiver)}&message=${encodeURIComponent(message)}`
            })
            .then(response => response.json())
            .then(data => alert(data.status))
            .catch(error => alert("❌ Error: " + error));
        }
    </script>
</head>
<body>
    <?php if (!isset($_SESSION['username'])): ?>
        <form onsubmit="registerUser(event)">
            <label>Enter your name:</label>
            <input type="text" name="username" id="username" required>
            <button type="submit">Start Chat</button>
        </form>
    <?php else: ?>
        <h2>Welcome, <?php echo htmlspecialchars($_SESSION['username']); ?>!</h2>
        
        <h3>Send Message</h3>
        <form onsubmit="sendMessage(event)">
            <input type="text" id="receiver" placeholder="Receiver's username" required>
            <input type="text" id="message" placeholder="Message" required>
            <button type="submit">Send</button>
        </form>

        <h3>Messages</h3>
        <ul id="messages"></ul>

        <form method="POST" action="logout.php">
            <button type="submit">Logout</button>
        </form>
    <?php endif; ?>
</body>
</html>
