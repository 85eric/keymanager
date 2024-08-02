package utils

import (
	"bytes"
	"context"
	"encoding/gob"
	"fmt"
	"strconv"

	idGen "github.com/orgNameToReplace/common/idgenerater"
)

const (
	SpanIdKey = "span_id"
)

func SetSpanId(ctx context.Context, spanId ...uint64) context.Context {
	value := uint64(0)
	if len(spanId) > 0 && spanId[0] != 0 {
		value = spanId[0]
	} else {
		value = idGen.NextID()
	}

	return context.WithValue(ctx, SpanIdKey, value)
}

func GetSpanId(ctx context.Context) uint64 {
	value, ok := ctx.Value(SpanIdKey).(uint64)
	if !ok {
		return idGen.NextID()
	}

	return value
}

func GobEncode(info interface{}) ([]byte, error) {
	buf := bytes.Buffer{}

	encoder := gob.NewEncoder(&buf)
	err := encoder.Encode(info)
	return buf.Bytes(), err
}

func GobDecode(data []byte, result interface{}) error {
	buf := bytes.Buffer{}

	decoder := gob.NewDecoder(&buf)
	buf.Write(data)
	return decoder.Decode(result)
}

func GetInput(fmtStr string, a ...interface{}) (string, error) {
	fmt.Println(fmt.Sprintf(fmtStr, a...))
	var info string
	_, err := fmt.Scanf("%s", &info)
	return info, err
}

func GetInputInt64(fmtStr string, a ...interface{}) (int64, error) {
	str, err := GetInput(fmtStr, a...)
	if err != nil {
		return 0, err
	}

	return strconv.ParseInt(str, 10, 64)
}
