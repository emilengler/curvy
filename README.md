# curvy

Brute-force vanity onion addresses.

## About

*curvy* is a tool very similar [mkp224o](https://github.com/cathugger/mkp224o).

Keep in mind that this is probably not the best tool for this task,
because it is written in a slow(er) language, as well as it ignoring the
advice for searching for vanity addresses given in the specification.

## Usage

```
$ curvy --prefix="foo" --output="./hs_ed25519_secret_key" --threads=64
foob64oywfdxkr4mxxio4xis6lba2peoplvj64kqbpybd2n6sqq6joqd.onion
```

## TODO

* [ ] Rewrite this in a language that natively supports threads and erases secret keys securely
