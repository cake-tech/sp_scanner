A sample command-line application with an entrypoint in `bin/`, library code
in `lib/`, and example unit test in `test/`.

## Building

to fix https://github.com/dart-lang/native/issues/338 do:

`.zshrc`
```zsh
export CPATH="$(clang -v 2>&1 | grep "Selected GCC installation" | rev | cut -d' ' -f1 | rev)/include"
```
or

`config.fish`
```fish
set -gx CPATH (clang -v 2>&1 | grep "Selected GCC installation" | rev | cut -d' ' -f1 | rev)/include
```

then

```shell
just
```
