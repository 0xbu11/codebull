//go:build go1.25 && !go1.27

package guard

func Check(start, end uint64) error {
	_, _ = start, end
	return nil
}
