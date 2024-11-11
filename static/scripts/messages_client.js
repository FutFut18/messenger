function encryptMessage(message, key) {
    const encrypted = CryptoJS.AES.encrypt(message, key).toString();
    return encrypted;
}

function decryptMessage(encryptedMessage, key) {
    const bytes = CryptoJS.AES.decrypt(encryptedMessage, key);
    const originalMessage = bytes.toString(CryptoJS.enc.Utf8);
    return originalMessage;
}

function sendMessage() {
    const messageField = document.getElementById('new_message_field');
    const oldMessageField = document.getElementById('old_message_field');
    const encryptionKey = document.getElementById('encryption_key').value;

    let message = messageField.value;

    if (encryptionKey) {
        message = encryptMessage(message, encryptionKey);
        message = `<<${message}>>`;
    }

    oldMessageField.value = message;

    fetch('/messages', {
        method: 'POST',
        body: new URLSearchParams({
            message_text: message,
            action: 'send_message'
        })
    }).then(response => response.json())
      .then(data => {
          messageField.value = '';
      })
      .catch(error => console.error('Ошибка отправки сообщения:', error));
}

document.getElementById('send_button').addEventListener('click', sendMessage);

function fetchMessages() {
    fetch('/poll_messages')
        .then(response => response.json())
        .then(data => {
            if (data.messages.length > 0) {
                const messagesContainer = document.getElementById('messages');
                messagesContainer.innerHTML = '';
                data.messages.forEach(msg => {
                    const regex = /<<(.+?)>>/;
                    const match = msg.match(regex);

                    let displayMessage = msg;
                    if (match) {
                        const encryptedMessage = match[1];
                        const encryptionKey = document.getElementById('encryption_key').value;
                        if (encryptionKey) {
                            const partBeforeDelimiter = msg.split('<<')[0];
                            const decryptedMessage = decryptMessage(encryptedMessage, encryptionKey);
                            displayMessage = partBeforeDelimiter + decryptedMessage;
                        }
                    }

                    const messageElement = document.createElement('div');
                    messageElement.textContent = displayMessage;
                    messagesContainer.appendChild(messageElement);
                });
                messagesContainer.scrollTop = messagesContainer.scrollHeight;
            }
        })
        .catch(error => console.error('Ошибка при получении сообщений:', error));
}

fetchMessages();
setInterval(fetchMessages, 500);