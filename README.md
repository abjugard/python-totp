In order for the tool to work, the configuration file must be encrypted with AES-256-CBC

e.g. openssl aes-256-cbc -salt -in otpkeys.example -out ~/.config/otpkeys.enc

An easy way to modify the configuration file is to use the `encvim` utility in my [dotfiles repository](https://github.com/abjugard/.dotfiles/blob/master/bin/encvim)
