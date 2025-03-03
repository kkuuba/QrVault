class QRVault {
    constructor(qr_vaul_url) {
        this.qr_vaul_url = qr_vaul_url
        const params = new URLSearchParams(window.location.search);
        if (params.get("data")) {
            document.getElementById('decrypt_qr_vault').classList.remove('hidden');
            document.getElementById('create_qr_vault').classList.add('hidden');
        }
        this.new_qr_vault_content = []

        let deferredPrompt;

        window.addEventListener('beforeinstallprompt', (event) => {
            event.preventDefault(); // Prevent automatic prompt
            deferredPrompt = event; // Store the event
            
            // Show the install button
            document.getElementById("installBtn").classList.remove("hidden");
        });
        
        document.getElementById("installBtn").addEventListener("click", async () => {
            if (deferredPrompt) {
                deferredPrompt.prompt(); // Show the install prompt
                
                const choice = await deferredPrompt.userChoice;
                if (choice.outcome === "accepted") {
                    console.log("User accepted the PWA install");
                } else {
                    console.log("User dismissed the PWA install");
                }
                
                deferredPrompt = null; // Reset the prompt
                document.getElementById("installBtn").classList.add("hidden");
            }
        });
        
        // Hide the button if app is already installed
        window.addEventListener("appinstalled", () => {
            document.getElementById("installBtn").classList.add("hidden");
            console.log("PWA installed");
        });

    }

    async generateQRCode(encryptionKey, dataForEncryption) {
        const qrVaultLink = await this.createQRVaultLink(encryptionKey, dataForEncryption);
        let qrDiv = document.getElementById("qrcode");
        let qrInfo = document.getElementById("qrcode_info");
        qrDiv.classList.remove('hidden');
        qrInfo.classList.remove('hidden');

        qrDiv.innerHTML = "";
        new QRCode(qrDiv, {
            text: qrVaultLink,
            width: 512,
            height: 512,
            correctLevel: QRCode.CorrectLevel.L, // Lowest error correction for max data storage
            version: 40 // Highest version (177x177 modules)
        });
    }

    async encryptData(dataToEncrypt, iv, encryptionKey) {
        const encoder = new TextEncoder();
        let paddedData = await this.pkcs7Pad(encoder.encode(dataToEncrypt));

        const encrypted = await crypto.subtle.encrypt(
            { name: "AES-CBC", iv },
            encryptionKey,
            paddedData
        );

        return this.arrayBufferToHex(encrypted);
    }

    async decryptData(dataToDecrypt, iv, encryptionKey) {
        const encryptedBytes = this.hexToArrayBuffer(dataToDecrypt);

        const decryptedPadded = await crypto.subtle.decrypt(
            { name: "AES-CBC", iv },
            encryptionKey,
            encryptedBytes
        );

        return this.pkcs7Unpad(new Uint8Array(decryptedPadded));
    }

    async deriveAESKeyFromPassword(password, salt) {
        const encoder = new TextEncoder();
        const keyMaterial = await crypto.subtle.importKey(
            "raw",
            encoder.encode(password),
            { name: "PBKDF2" },
            false,
            ["deriveKey"]
        );

        return await crypto.subtle.deriveKey(
            {
                name: "PBKDF2",
                salt,
                iterations: 100000,
                hash: "SHA-256"
            },
            keyMaterial,
            { name: "AES-CBC", length: 256 },
            true,
            ["encrypt", "decrypt"]
        );
    }

    async createQRVaultLink(encryptionKey, dataForEncryption) {
        const iv = crypto.getRandomValues(new Uint8Array(16));
        const salt = crypto.getRandomValues(new Uint8Array(16));
        const aesKey = await this.deriveAESKeyFromPassword(encryptionKey, salt);
        const jsonData = JSON.stringify(dataForEncryption);
        const encryptedData = await this.encryptData(jsonData, iv, aesKey);

        return `${this.qr_vaul_url}/?data=${encryptedData}&iv=${this.arrayBufferToHex(iv)}&salt=${this.arrayBufferToHex(salt)}`;
    }

    async retrieveQRVaultSecureInfo(decryptionKey, saltHex, ivHex, dataForDecryption) {
        const salt = this.hexToArrayBuffer(saltHex);
        const iv = this.hexToArrayBuffer(ivHex);
        const aesKey = await this.deriveAESKeyFromPassword(decryptionKey, salt);
        const decryptedData = await this.decryptData(dataForDecryption, iv, aesKey);

        return JSON.parse(decryptedData);
    }

    arrayBufferToHex(buffer) {
        return Array.from(new Uint8Array(buffer))
            .map(byte => byte.toString(16).padStart(2, "0"))
            .join("");
    }

    hexToArrayBuffer(hex) {
        let bytes = new Uint8Array(hex.length / 2);
        for (let i = 0; i < bytes.length; i++) {
            bytes[i] = parseInt(hex.substr(i * 2, 2), 16);
        }
        return bytes.buffer;
    }

    async pkcs7Pad(data) {
        const blockSize = 16;
        const padLength = blockSize - (data.length % blockSize);
        const paddedData = new Uint8Array(data.length + padLength);
        paddedData.set(data);
        paddedData.fill(padLength, data.length);
        return paddedData;
    }

    pkcs7Unpad(data) {
        const padLength = data[data.length - 1];
        return new TextDecoder().decode(data.slice(0, -padLength));
    }

    async generateQrVault() {
        let json_data = JSON.stringify(this.new_qr_vault_content)
        const encryptionKey = document.getElementById("encrypt_key").value;
        const repeatencryptionKey = document.getElementById("repeat_encrypt_key").value;
        if (!encryptionKey || !json_data) {
            alert("Please enter both password and data.");
            return;
        }
        if (encryptionKey != repeatencryptionKey) {
            alert("Encryption keys are not the same");
            return;
        }
    
        await this.generateQRCode(encryptionKey, json_data);
    }


    // Handle Decrypt QR
    async decryptQrVault() {
        const decryptionKey = document.getElementById("decrypt-password").value;
        const params = new URLSearchParams(window.location.search);
        const encryptedText = params.get("data"); // "John"
        const saltHex = params.get("salt"); // "25"
        const ivHex = params.get("iv"); // "25"

        if (!decryptionKey || !encryptedText || !saltHex || !ivHex) {
            alert("Please enter all required fields.");
            return;
        }
        try {
            const decryptedData = await this.retrieveQRVaultSecureInfo(
                decryptionKey, saltHex, ivHex, encryptedText
            );

            const tableBody = document.getElementById("decrypted-table-body");
            tableBody.innerHTML = ""; // Clear previous content

            // Loop through each dictionary (object) and create table rows
            JSON.parse(decryptedData).forEach(item => {
                const row = `
                    <tr class="border">
                        <td class="py-2 px-4 border">${item[0]}</td>
                        <td class="py-2 px-4 border">${item[1]}</td>
                        <td class="py-2 px-4 border">${item[2]}</td>
                    </tr>`;
                tableBody.innerHTML += row;
            });

            document.getElementById('table-container').classList.remove('hidden');

        } catch (error) {
            console.log(error)
            alert("Decryption failed. Check your password or input data.");
        }
    }

    addNewEntryForQrVault() {
        // Get input values
        const service = document.getElementById("service").value.trim();
        const username = document.getElementById("username").value.trim();
        const password = document.getElementById("password").value.trim();
    
        // Validate inputs
        if (!service || !username || !password) {
            alert("Please fill in all fields!");
            return;
        }
    
        // Create a dictionary (object)
        const dataEntry = [service, username, password];
    
        // Add to list
        this.new_qr_vault_content.push(dataEntry);
    
        // Update table
        this.updateTable();
    
        // Clear input fields
        document.getElementById("service").value = "";
        document.getElementById("username").value = "";
        document.getElementById("password").value = "";
    }
    
    updateTable() {
        const tableBody = document.getElementById("data-table-body");
        tableBody.innerHTML = ""; // Clear table before updating
    
        // Populate table with data
        this.new_qr_vault_content.forEach(item => {
            const row = `
                <tr>
                    <td class="py-2 px-4 border">${item[0]}</td>
                    <td class="py-2 px-4 border">${item[1]}</td>
                    <td class="py-2 px-4 border">${item[2]}</td>
                </tr>
            `;
            tableBody.innerHTML += row;
        });
    }

    showInfoMessage() {
        document.getElementById("pwaDetails").innerHTML  = `
            This tool lets you securely store your passwords by encrypting them into a QR code. Your data is never stored on any server - only within the QR code itself. It can only be decrypted with a unique key after scanning, ensuring your credentials remain private, portable, and accessible only to you.
        `;
        document.getElementById("modal").classList.remove("hidden");
    }

    closeInfoMessage() {
        document.getElementById("modal").classList.add("hidden");
    }
}

// Initialize Vault
let qr_vault = new QRVault("https://kkuuba.github.io/QrVault");
