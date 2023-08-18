# feistel
Obfuscate sequential sequences

This package provides functions to map a value in a range to another value in the same
range, and to map it back again. This is useful for mapping a sequence of successive
integers to an apparently random order, e.g. to obfuscate a database primary key where
it is used in a user visible way.

```go
encoded, _ := Encrypt(42, 0, 100, 0xf00f)
decoded, _ := Decrypt(encoded, 0, 100, 0xf00f)
fmt.Printf("42 -> %d -> %d", encoded, decoded)
// Output:
// 42 -> 62 -> 42
```
