package detector

import "math"

// ComputeShannonEntropy computes the Shannon entropy (base 2) of a string.
func ComputeShannonEntropy(s string) float64 {
	if len(s) == 0 {
		return 0
	}
	freq := make(map[rune]float64)
	for _, r := range s {
		freq[r]++
	}
	var entropy float64
	length := float64(len(s))
	for _, c := range freq {
		p := c / length
		entropy += -p * math.Log2(p)
	}
	return entropy
}
