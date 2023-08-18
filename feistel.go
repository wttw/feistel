package feistel

import "fmt"

// Taken from the postgresql extension at https://github.com/dverite/permuteseq
// Not bit for bit identical; we don't use the postgresql hash functions, for one

// Encrypt reversibly maps a value in the range (minVal .. maxVal) to another value
// in that range.
func Encrypt(value, minVal, maxVal int64, cryptKey uint64) (int64, error) {
	return cycleWalkingCipher(value, minVal, maxVal, cryptKey, false)
}

// Decrypt maps a value that had previously been created by Encrypt back to it's
// original value.
func Decrypt(value, minVal, maxVal int64, cryptKey uint64) (int64, error) {
	return cycleWalkingCipher(value, minVal, maxVal, cryptKey, true)
}

func cycleWalkingCipher(value, minVal, maxVal int64, cryptKey uint64, decrypt bool) (int64, error) {
	if value < minVal || value > maxVal {
		return 0, fmt.Errorf("%d is outside the range (%d, %d)", value, minVal, maxVal)
	}
	// Arbitrary maximum number of "walks" along the results
	// searching for a value inside the [minval,maxval] range.
	// It's mainly to avoid an infinite loop in case the chain of
	// results has a cycle (which would imply a bug somewhere).
	const walkMax = 1000000

	// Half block size
	var hsz = 1

	// Number of possible values for the output
	interval := uint64(maxVal - minVal + 1)
	var mask, ki uint32

	// Number of rounds of the Feistel Network. Must be at least 3.
	const nr = 9

	var l1, r1, l2, r2 uint32
	walkCount := 0
	var result uint64

	for hsz < 32 && (uint64(1)<<(2*hsz)) < interval {
		hsz++
	}

	mask = (1 << hsz) - 1
	// Scramble the key. This is not strictly necessary, but will
	// help if the user-supplied key is weak, for instance with only a
	// few right-most bits set.
	cryptKey = uint64(hashUint32(uint32(cryptKey))) |
		uint64(hashUint32(uint32(cryptKey>>32)))<<32

	// Initialize the two half blocks.
	// Work with the offset into the interval rather than the actual value.
	// This allows to use the full 32-bit range.
	l1 = uint32(uint64(value-minVal) >> hsz)
	r1 = uint32(uint64(value-minVal) & uint64(mask))

	for { // cycle walking
		for i := 0; i < nr; i++ { // Feistel network
			l2 = r1
			// The subkey Ki for the round i is a sliding and cycling window
			// of hsz bits over K, moving left to right, so each round takes
			// different bits out of the crypt key. The round function is
			// simply hash(Ri) XOR hash(Ki).
			// When decrypting, Ki corresponds to the Kj of encryption with
			// j=(NR-1-i), i.e. we iterate over subkeys in the reverse order.
			if decrypt {
				ki = uint32(cryptKey >> ((hsz * (nr - 1 - i)) & 0x3f))
				ki += uint32(nr - 1 - i)
			} else {
				ki = uint32(cryptKey >> (hsz * i))
				ki += uint32(i)
			}
			r2 = ((l1 ^ hashUint32(r1)) ^ hashUint32(ki)) & mask
			l1 = l2
			r1 = r2
		}
		result = (uint64(r1) << hsz) | uint64(l1)
		// swap one more time to prepare for the next cycle
		l1 = r2
		r1 = l2
		walkCount++
		if !(result > uint64(maxVal-minVal) && walkCount < walkMax) {
			break
		}
	}
	if walkCount >= walkMax {
		return 0, fmt.Errorf("infinite cycle walking prevented for %d (%d loops)", value, walkMax)
	}
	return minVal + int64(result), nil
}

func hashUint32(k uint32) uint32 {
	return (0x811c9dc5 ^ k) * 0x01000193
}
