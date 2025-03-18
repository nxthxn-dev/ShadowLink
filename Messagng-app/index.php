<?php
session_start();
$server_url = "http://localhost:8000";

// Ensure the keys directory exists
$keys_dir = __DIR__ . "/keys";
if (!is_dir($keys_dir)) {
    mkdir($keys_dir, 0777, true);
}

// Generate or load RSA keys for the user
if (isset($_SESSION['username'])) {
    $username = $_SESSION['username'];
    $publicKeyPath = "$keys_dir/{$username}_public.pem";
    $privateKeyPath = "$keys_dir/{$username}_private.pem";

    if (!file_exists($publicKeyPath) || !file_exists($privateKeyPath)) {
        $keypair = openssl_pkey_new([
            "private_key_bits" => 2048,
            "private_key_type" => OPENSSL_KEYTYPE_RSA,
        ]);

        if (!$keypair) {
            die("❌ Error: Failed to generate RSA key pair. Check OpenSSL configuration.");
        }

        openssl_pkey_export($keypair, $privateKey);
        file_put_contents($privateKeyPath, $privateKey);

        $keyDetails = openssl_pkey_get_details($keypair);
        $publicKey = $keyDetails["key"];
        file_put_contents($publicKeyPath, $publicKey);
    }

    $publicKey = openssl_pkey_get_public(file_get_contents($publicKeyPath));
    $privateKey = openssl_pkey_get_private(file_get_contents($privateKeyPath));

    if (!$publicKey || !$privateKey) {
        die("❌ Error loading keys! Check your PEM files.");
    }
}

// Handle username submission
if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['username'])) {
    $_SESSION['username'] = trim($_POST['username']);
    header("Location: " . $_SERVER['PHP_SELF']);
    exit();
}

// Handle message sending
if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['message'])) {
    if (!isset($_SESSION['username'])) {
        die("❌ Error: Username not set. Please enter your name first.");
    }

    $message = trim($_POST['message']);
    $username = $_SESSION['username'];

    // Encrypt message
    openssl_public_encrypt($message, $encrypted_message, $publicKey);
    $encrypted_message_hex = bin2hex($encrypted_message);

    // Sign message
    openssl_sign($message, $signature, $privateKey, OPENSSL_ALGO_SHA512);
    $signature_hex = bin2hex($signature);

    $data = [
        'sender' => $username,
        'content' => $encrypted_message_hex,
        'signature' => $signature_hex
    ];

    $options = [
        'http' => [
            'header'  => "Content-Type: application/json",
            'method'  => 'POST',
            'content' => json_encode($data)
        ]
    ];

    $context  = stream_context_create($options);
    file_get_contents("$server_url/send/", false, $context);
}

// Clear chat
if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['clear_chat'])) {
    file_get_contents("$server_url/clear/", false, stream_context_create(['http' => ['method'  => 'DELETE']]));
}
?>

<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>Secure Chat</title>
    <link rel="stylesheet" href="apple.css">
    <script>
        let ws = new WebSocket("ws://localhost:8000/ws");

        ws.onmessage = function(event) {
            let data = JSON.parse(event.data);
            let messagesList = document.getElementById("messages");
            let li = document.createElement("li");

            let messageText = `<strong>${data.sender}:</strong> ${data.content}`;
            if (data.status) {
                messageText += ` <span>${data.status}</span>`;  // Only add status if it exists
            }

            li.innerHTML = messageText;
            messagesList.appendChild(li);
        };

        function sendMessage(event) {
            event.preventDefault();
            let messageInput = document.getElementById("message");
            let message = messageInput.value;
            let sender = "<?php echo $_SESSION['username'] ?? 'Anonymous'; ?>";

            if (message.trim() === "") return;

            ws.send(JSON.stringify({ sender: sender, content: message }));
            messageInput.value = "";
        }
    </script>
</head>
<body>
    <?php if (!isset($_SESSION['username'])): ?>
        <form method="POST">
            <label>Enter your name:</label>
            <input type="text" name="username" required>
            <button type="submit">Start Chat</button>
        </form>
    <?php else: ?>
        <h2>Welcome, <?php echo htmlspecialchars($_SESSION['username']); ?>!</h2>
        <h2>Messages</h2>
        <ul id="messages"></ul>
        <form onsubmit="sendMessage(event)">
            <input type="text" id="message" required>
            <button type="submit">Send</button>
        </form>
        <form method="POST">
            <input type="hidden" name="clear_chat" value="1">
            <button type="submit">Clear Chat</button>
        </form>
        <form method="POST" action="logout.php">
            <button type="submit">Logout</button>
        </form>
    <?php endif; ?>
</body>
</html>
