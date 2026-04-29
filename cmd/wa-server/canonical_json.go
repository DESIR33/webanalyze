package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"math"
	"sort"
	"strconv"
)

// canonicalJSONHash returns SHA-256 hex of canonical JSON per idempotency spec:
// parse JSON, re-serialize with sorted object keys, compact spacing, stable numbers.
func canonicalJSONHash(raw []byte) (digestHex string, canonicalLen int, err error) {
	var v any
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.UseNumber()
	if err := dec.Decode(&v); err != nil {
		return "", 0, err
	}
	if _, err := dec.Token(); err != io.EOF {
		if err == nil {
			return "", 0, errors.New("trailing json")
		}
		return "", 0, err
	}
	canonical, err := marshalCanonical(v)
	if err != nil {
		return "", 0, err
	}
	sum := sha256.Sum256(canonical)
	return hex.EncodeToString(sum[:]), len(canonical), nil
}

func marshalCanonical(v any) ([]byte, error) {
	var buf bytes.Buffer
	if err := writeCanonical(&buf, v); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

func writeCanonical(buf *bytes.Buffer, v any) error {
	switch x := v.(type) {
	case nil:
		buf.WriteString("null")
	case bool:
		if x {
			buf.WriteString("true")
		} else {
			buf.WriteString("false")
		}
	case float64:
		writeFloat(buf, x)
	case json.Number:
		f, err := x.Float64()
		if err != nil {
			buf.WriteString(x.String())
			return nil
		}
		writeFloat(buf, f)
	case string:
		enc, err := json.Marshal(x)
		if err != nil {
			return err
		}
		buf.Write(enc)
	case []any:
		buf.WriteByte('[')
		for i, el := range x {
			if i > 0 {
				buf.WriteByte(',')
			}
			if err := writeCanonical(buf, el); err != nil {
				return err
			}
		}
		buf.WriteByte(']')
	case map[string]any:
		keys := make([]string, 0, len(x))
		for k := range x {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		buf.WriteByte('{')
		for i, k := range keys {
			if i > 0 {
				buf.WriteByte(',')
			}
			keyEnc, err := json.Marshal(k)
			if err != nil {
				return err
			}
			buf.Write(keyEnc)
			buf.WriteByte(':')
			if err := writeCanonical(buf, x[k]); err != nil {
				return err
			}
		}
		buf.WriteByte('}')
	default:
		// json.Unmarshal only produces the types above; fall back to round-trip
		b, err := json.Marshal(x)
		if err != nil {
			return err
		}
		var v2 any
		if err := json.Unmarshal(b, &v2); err != nil {
			buf.Write(b)
			return nil
		}
		return writeCanonical(buf, v2)
	}
	return nil
}

func writeFloat(buf *bytes.Buffer, f float64) {
	if math.IsNaN(f) || math.IsInf(f, 0) {
		buf.WriteString("null")
		return
	}
	if f == 0 {
		buf.WriteString("0")
		return
	}
	if f == math.Trunc(f) && f >= -1e15 && f <= 1e15 && f == float64(int64(f)) {
		buf.WriteString(strconv.FormatInt(int64(f), 10))
		return
	}
	buf.WriteString(strconv.FormatFloat(f, 'g', -1, 64))
}
