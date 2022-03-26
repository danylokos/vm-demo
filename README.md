# `vm_*` APIs usage demo

## Build & sign

1. Get code signing identity

 `security find-identity`

2. Set `IDENTITY` env var

 `export IDENTITY="Apple Development: Danylo Kostyshyn (XXXXXXXXXX)"`

3. Build

 `make all`

4. Run

 `./runner demo`

## Output

Normal binary:

```sh
mbp:~ ./demo
[demo] Enter two numbers: 3 4
[demo] 3 + 4 = 7
```

Patched binary:

```sh
mbp:~ ./runner --path demo
[*] Preparing to execute binary demo
[+] Child process created with pid: 53159
[*] Patching child process...
[*] Image mapped at 0x104f71000
[*] Patching _add func...
[*] _add at offset 0x3ec0 in demo
[*] Patching '+' sign...
[+] Successfully patched
[*] Sending SIGCONT to continue child
[demo] Enter two numbers: 3 4
[demo] 3 * 4 = 12
```

## Links

1. [Fuzzing iOS code on macOS at native speed](https://googleprojectzero.blogspot.com/2021/05/fuzzing-ios-code-on-macos-at-native.html)
