package common

const (
	DefaultSecretLength = 32
)

var (
	KeyManagerDefaultSuffix = []byte("key Manager")
	MPCNodeDefaultSuffix    = []byte("mpc Node")

	SplitKeysIndex = [][]int{
		[]int{4, 5, 6, 7, 8, 9},
		[]int{1, 2, 3, 7, 8, 9},
		[]int{0, 2, 3, 5, 6, 9},
		[]int{0, 1, 3, 4, 6, 8},
		[]int{0, 1, 2, 4, 5, 7},
	}
)
