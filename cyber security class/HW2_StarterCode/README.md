# Homework 2 Starter Package

This package contains the starter code for the CTR bit-flipping, CTR
format-oracle, and CBC padding-oracle attacks in Homework 2.

## Files

- `oracle.py` — vulnerable services and oracle implementations. Treat these as
  black boxes and use only the public interfaces described in the homework.
- `attacks.py` — the only starter-code file you should modify.
- `test_public.py` — a small public test suite.
- `README.md` — these setup instructions.

For submission, follow the homework handout: submit a `.zip` containing exactly
`answers.pdf` and `attacks.py`. Do **not** include the other starter files.

## Requirements

Python 3.10+ is recommended.

Install the required dependency:

```bash
python -m pip install pycryptodome
```

## Run the public tests

From this directory, run:

```bash
python -m unittest -v test_public.py
```

Initially, the tests fail with `NotImplementedError`. As you implement the
required functions in `attacks.py`, the corresponding tests should begin to
pass.

The public tests are intentionally limited. Your code will be graded using
fresh random keys and fresh random messages, including the edge cases described
in the homework handout.
