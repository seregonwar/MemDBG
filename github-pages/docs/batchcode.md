Batchcode is a simple scripting language for trainer logic. Each line is a command; empty lines and lines starting with `#` are ignored.

## Commands

| Command | Syntax | Description |
|---|---|---|
| `WRITE` | `WRITE addr value` | Write a value to an absolute address. |
| `READ` | `READ addr type` | Read a value for comparison. |
| `IF` | `IF addr op value` | Conditional: skip next line if false. |
| `LOCK` | `LOCK addr value interval_ms` | Continuously rewrite a value. |
| `UNLOCK` | `UNLOCK addr` | Stop locking an address. |
| `WAIT` | `WAIT ms` | Pause execution for N milliseconds. |

## Operators

`==` `!=` `<` `<=` `>` `>=`

## Example

```batchcode
# Infinite health trainer
LOCK 0x12ABC0 999 100
WAIT 5000
READ 0x12ABC0 u32
IF 0x12ABC0 == 999
  WRITE 0x12DEF0 1
```
