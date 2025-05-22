# EX No. 13 : MESSAGE AUTHENTICATION CODE (MAC)

#### Name : Prajin S
#### Register Number : 212223230151

## AIM:
To implement MESSAGE AUTHENTICATION CODE(MAC)

## ALGORITHM:

### Step 01:
Message Authentication Code (MAC) is a cryptographic technique used to verify the integrity and authenticity of a message by using a secret key.

### Step 02: Initialization
   - Choose a cryptographic hash function \( H \) (e.g., SHA-256) and a secret key \( K \).
   - The message \( M \) to be authenticated is input along with the secret key \( K \).

### Step 03: MAC Generation
   - Compute the MAC by applying the hash function to the combination of the message \( M \) and the secret key \( K \): 
     \[
     \text{MAC}(M, K) = H(K || M)
     \]
     where \( || \) denotes concatenation of \( K \) and \( M \).

### Step 04: Verification
   - The recipient, who knows the secret key \( K \), computes the MAC using the received message \( M \) and the same hash function.
   - The recipient compares the computed MAC with the received MAC. If they match, the message is authentic and unchanged.

### Step 05: Security
The security of the MAC relies on the secret key \( K \) and the strength of the hash function \( H \), ensuring that an attacker cannot forge a valid MAC without knowledge of the key.

## Program:
```C
#include <stdio.h>
#include <string.h>

#define MAC_SIZE 16  // Smaller size for simplicity

// Simple MAC computation using XOR + addition (not secure, for demo only)
void computeMAC(const char *key, const char *message, unsigned char *mac) {
    int key_len = strlen(key);
    int msg_len = strlen(message);

    for (int i = 0; i < MAC_SIZE; i++) {
        mac[i] = 0;
        for (int j = 0; j < msg_len; j++) {
            mac[i] ^= (message[j] + key[(i + j) % key_len]);
        }
    }
}

int main() {
    char key[100], message[100];
    unsigned char mac[MAC_SIZE];
    unsigned char receivedMAC[MAC_SIZE];

    printf("Enter the secret key: ");
    scanf("%s", key);

    printf("Enter the message: ");
    scanf("%s", message);

    computeMAC(key, message, mac);

    // Print computed MAC
    printf("Computed MAC (in hex): ");
    for (int i = 0; i < MAC_SIZE; i++) {
        printf("%02x", mac[i]);
    }
    printf("\n");

    // Get received MAC from user
    printf("Enter the received MAC (in hex, %d bytes): ", MAC_SIZE);
    for (int i = 0; i < MAC_SIZE; i++) {
        scanf("%2hhx", &receivedMAC[i]);
    }

    // Compare MACs
    if (memcmp(mac, receivedMAC, MAC_SIZE) == 0) {
        printf("MAC verification successful. Message is authentic.\n");
    } else {
        printf("MAC verification failed. Message is not authentic.\n");
    }

    return 0;
}
```


## Output:
Enter the secret key: prajin

Enter the message: macincrypto

Computed MAC (in hex): c1e9c1d4f9e6c1e9c1d4f9e6c1e9c1d4

Enter the received MAC (in hex, 16 bytes): c1e9c1d4f9e6c1e9c1d4f9e6c1e9c1d4

MAC verification successful. Message is authentic.

![Screenshot 2025-05-17 145611](https://github.com/user-attachments/assets/53286ab4-cd96-4d23-bbf1-d90fe79b6ed8)

![Screenshot 2025-05-17 145622](https://github.com/user-attachments/assets/0fa356c0-39ce-4231-9d73-df8bcd72bb2d)


## Result:
The program is executed successfully and results are verified as well.
