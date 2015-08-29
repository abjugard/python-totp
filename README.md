In order for the tool to work, the configuration file must be encrypted with AES-256-CBC

e.g. openssl aes-256-cbc -salt -in otpkeys.example -out ~/.config/otpkeys.enc
