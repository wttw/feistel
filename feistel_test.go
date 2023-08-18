package feistel

import (
	"fmt"
	"testing"
)

func TestErrors(t *testing.T) {
	tests := map[string]struct {
		Val int64
		Min int64
		Max int64
		Key uint64
	}{
		"below_range":    {1, 5, 10, 0},
		"above_range":    {15, 5, 10, 0},
		"inverted_range": {5, 10, 1, 0},
	}
	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			_, err := Encrypt(test.Val, test.Min, test.Max, test.Key)
			if err == nil {
				t.Error("expected error, got nil")
			}
			_, err = Decrypt(test.Val, test.Min, test.Max, test.Key)
			if err == nil {
				t.Error("expected error, got nil")
			}
		})
	}
}

// TestExhaustive encodes and decode every value in a range and checks the results are in range and unique
// (there's no need to explicitly check for uniqueness, as we round trip everything, but it's cheap)
func TestExhaustive(t *testing.T) {
	tests := []struct {
		Min int64
		Max int64
		Key uint64
	}{
		{1, 10, 0xdeadbeef},
		{1, 100, 0xdeadbeef},
		{1, 10, 0},
		{100000, 100100, 0xf00b},
		{-400, -300, 0x1},
	}
	for _, test := range tests {
		t.Run(fmt.Sprintf("range_%d_%d", test.Min, test.Max), func(t *testing.T) {
			seen := map[int64]int64{}
			for i := test.Min; i <= test.Max; i++ {
				enc, err := Encrypt(i, test.Min, test.Max, test.Key)
				if err != nil {
					t.Errorf("encode %d failed: %s", i, err)
					continue
				}
				//fmt.Printf("%d -> %d\n", i, enc)
				if enc < test.Min || enc > test.Max {
					t.Errorf("result out of range %d -> %d", i, enc)
				}
				dec, err := Decrypt(enc, test.Min, test.Max, test.Key)
				if err != nil {
					t.Errorf("decode %d failed: %s", dec, err)
					continue
				}
				if dec != i {
					t.Errorf("round trip failed %d -> %d -> %d", i, enc, dec)
				}
				v, ok := seen[enc]
				if ok {
					t.Errorf("%d and %d both encode to %d", i, v, enc)
				}
				seen[enc] = i
			}
		})
	}
}

func Example() {
	encoded, _ := Encrypt(42, 0, 100, 0xf00f)
	decoded, _ := Decrypt(encoded, 0, 100, 0xf00f)
	fmt.Printf("42 -> %d -> %d", encoded, decoded)
	// Output:
	// 42 -> 62 -> 42
}
