## 🐕 prompter

`prompter` is a tool to automatically fill OTP tokens into SSH connections,
while storing the secret data in the macOS Keychain.

### Installation

```shell
go install github.com/unkaktus/prompter
```

### Usage

Add new item to the macOS Keychain with the "Where" set to "prompter",
"Account" set to the SSH hostname, and with the following content"

```json
{"password":"password_string","totp_url":"otpauth://totp/..."}
```

where `password` is your password and `totp_url` is your TOTP URL
(can be obtained by reading the QR code data).

Once set, login to the node embracing your hostname in curly braces:

```shell
prompter ssh {lunar}
```
